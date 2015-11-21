(ns digest-store.utils
  (:use [clojure.string :only [split]])
  (:import [org.apache.commons.codec.binary Base32 Base64 Hex]
           [java.net URI URL]
           [java.util UUID]
           [java.nio ByteBuffer]
           [java.security MessageDigest])
)

(defmulti base32-encode
  (fn [x] (class x)))

(defmethod base32-encode (Class/forName "[B") [b]
  (first (split (.toLowerCase (String. (.encode (Base32. 0) b))) #"=")))

(defmethod base32-encode String [s]
  (base32-encode (.getBytes s)))

;; (defn base32-encode
;;   "Encode a base32 string"
;;   ;; Base32 constructor with an argument of 0 means no line separator
;;   ([^String s]
;;    (base32-encode (.getBytes s)))
;;   ([^bytes b] 

(defn base32-decode [str]
  "Decode a base32 string into uh, something?"
  (.decode (Base32.) (.toUpperCase str)))

(defn base32-to-hex-string [str]
  (String. (.encode (Hex.) (base32-decode str))))

(defmulti base64-encode (fn [s & urlsafe] (type s)))

(defmethod base64-encode (Class/forName "[B") [b & urlsafe]
  (first (split (String. (.encode
                          (Base64. 0 (byte-array 0) 
                                   (boolean urlsafe)) b)) #"=")))

(defmethod base64-encode String [s & urlsafe]
  (base64-encode (.getBytes s) urlsafe))

(defn base64-decode [str] (.decode (Base64.) str))
  

(defprotocol URICoercions
  (as-uri [x] "Coerce the thing to a java.net.URI"))

(extend-protocol URICoercions
  String
  (as-uri [s] (URI. s))
  java.io.File
  (as-uri [f] (.toURI f))
  URL
  (as-uri [u] (as-uri (.toString u)))
  URI
  (as-uri [u] u)
  UUID
  (as-uri [u] (as-uri (str "urn:uuid:" u)))
  MessageDigest
  (as-uri [m]
    (as-uri (str "ni:///" (.getAlgorithm m) ";"
                 (String. (.encode
                           (Base64. 0 (byte-array 0) true) (.digest m))))))
  )

(defn uuid-urn []
  "Make a random (V4) urn:uuid:..."
  (as-uri (. UUID randomUUID)))

(defn- ni-uri-split [uri]
  (vec (rest (re-find #"^/*([^;]+);+(.*?)$" (.getPath (as-uri uri))))))

(defn ni-uri-algorithm [uri]
  "Retrieve the algorithm string in an ni: URI"
  (first (ni-uri-split (as-uri uri))))

(defn ni-uri-digest [uri]
  "Retrieve the (hexadecimal) digest from an ni: URI"
  (let [[algo b64digest] (ni-uri-split uri)
        ;; base64 constructor is url safe
        digest (.decode (Base64. true) b64digest)]
    (String. (.encode (Hex.) digest))))

(defn uuid-to-ncname
  "Turn a UUID into a NCName."
  [uuid & no-case]
  (let [version (char (+ (.version uuid) 65))
        hi (.getMostSignificantBits uuid)
        lo (.getLeastSignificantBits uuid)
        ;; remove version bits from hi and add top 4 bits from lo.
        hi-mod (bit-or (bit-and hi (bit-not 16rffff))
                          (bit-shift-left (bit-and hi 16rfff) 4)
                          (bit-and (bit-shift-right lo 60) 16rf))
        ;; shift low half of uuid 4 bits to the left, then the last
        ;; byte to the right, one bit for base32 and two for base64.
        lo-mod (bit-or (bit-and (bit-shift-left lo 4) (bit-not 16rff))
                           (bit-shift-right
                            (bit-and (bit-shift-left lo 4) 16rff)
                            (if no-case 1 2)))
        ;; snarf contents up into a byte buffer and then byte array.
        bb (.array
            (doto (. ByteBuffer allocate (* (/ (. Long SIZE) (. Byte SIZE)) 2))
              (.putLong hi-mod) (.putLong lo-mod)))]
    ;;(println (format "%s %x %x" uuid hi-mod lo-mod))

    ;; concatenate version and encoded uuid. remove last character
    ;; which is always zero
    (str version
         (let [x (if no-case (base32-encode bb) (base64-encode bb true))]
           (subs x 0 (- (.length x) 1))))))

(defn ncname-to-uuid
  "Turn an NCName-encoded UUID string into a UUID object."
  [ncname]
  (let [[_ v s] (re-find #"^([A-Pa-p])([0-9A-Za-z/+_-]{21,26})$" ncname)
        ;; codec truncates rather than pads, so we add an A (zero).
        content (if s (if (zero? (mod (.length s) 2)) s (str s "A"))
                    (throw (IllegalArgumentException.
                            (str ncname " is not a valid NCname"))))
        ;; we know this input is okay or it would have thrown already.
        version (- (byte (first (.toUpperCase v))) 65)
        ;; ncname is case-insensitive (base32) if longer than 22 chars.
        no-case (if (> (.length content) 22) true false)
        decoder (if no-case base32-decode base64-decode)
        ;; here's the byte buffer again
        bb (doto
               (. ByteBuffer allocate (* (/ (. Long SIZE) (. Byte SIZE)) 2))
             (.put (decoder content))
             (.rewind))
        hi (.getLong bb)
        lo (.getLong bb)
        hi-mod (bit-or (bit-and hi (bit-not 16rffff))
                       (bit-shift-left version 12)
                       (bit-shift-right (bit-and hi 16rffff) 4))
        ;; fix the last byte because this shit is confusing
        lo-tmp (bit-or (bit-and lo (bit-not 16rff))
                       (bit-shift-left (bit-and lo 16rff)
                                       (if no-case 1 2)))
        lo-mod (bit-or
                (bit-shift-left hi 60)
                (bit-and (bit-shift-right lo-tmp 4)
                         (bit-not (bit-shift-left 16rf 60))))
        ]
    ;;(println (format "%x %x %x" hi-mod lo-tmp lo-mod))
    ;; and that's that
    (UUID. hi-mod lo-mod)))

