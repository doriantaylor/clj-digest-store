(ns digest-store.utils
  (:use [clojure.string :only [split]])
  (:import [org.apache.commons.codec.binary Base32 Base64 Hex]
           [java.net URI URL]
           [java.util UUID]
           [java.nio ByteBuffer]
           [java.security MessageDigest])
)

;; base64 stuff

(defmulti base64-encode
  "Turn a string or byte array into a Base64 string."
  (fn [s & urlsafe] (type s)))

(defmethod base64-encode (Class/forName "[B") [b & urlsafe]
  (first (split (String. (.encode
                          (Base64. 0 (byte-array 0) 
                                   (boolean urlsafe)) b)) #"=")))

(defmethod base64-encode String [s & urlsafe]
  (base64-encode (.getBytes s) urlsafe))

(defn base64-decode
  "Turn a Base64 string or byte array into a decoded byte array."
  [str] (.decode (Base64.) str))

;; base32 stuff

(defmulti base32-encode
  "Turn a string or byte array into a Base32 string."
  (fn [x] (type x)))

;; for the record i don't know how else to say byte array
(defmethod base32-encode (Class/forName "[B") [b]
  (first (split (.toLowerCase (String. (.encode (Base32. 0) b))) #"=")))

(defmethod base32-encode String [s]
  (base32-encode (.getBytes s)))

(defn base32-decode [str]
  "Turn a Base32 string or byte array into a decoded byte array."
  (.decode (Base32.) (.toUpperCase str)))

;; hexadecimal stuff

(defmulti hex-encode
  "Turn a string or byte array into a hexadecimal string."
  (fn [str & upper-case] (type str)))

(defmethod hex-encode (Class/forName "[B") [b & upper-case]
  (let [s (String. (.encode (Hex.) b))]
    (if upper-case (.toUpperCase s) (.toLowerCase s))))

(defmethod hex-encode String [s & upper-case]
  (hex-encode (.getBytes s)))

;; this little guy can probably get nuked

(defn base32-to-hex-string [str]
  (String. (.encode (Hex.) (base32-decode str))))

;; uri stuff

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

;; uuid stuff

(defmulti uuid
  "Create a UUID object from a string or URI, or generate a random one."
  (fn
    ([x] (type x))
    ([] :default)))

(defmethod uuid
;;  "Make a UUID from a string."
  String [s] (UUID/fromString s))

(defmethod uuid
;;  "Make a UUID from a urn:uuid URI object."
  URI [u] (let [[_ s] (re-find #"^(?i:urn:uuid:)([0-9A-Fa-f-]+)$"
                               (.toString u))]
            (if (nil? s) (throw (IllegalArgumentException.
                                 (str u " not a urn:uuid")))
                (uuid s))))

(defmethod uuid
  :default [] (. UUID randomUUID))

(defmethod uuid
  nil [_] (uuid))

(defn uuid-urn
  "Make a urn:uuid:..."
  [& u]
  (println u)
  (as-uri (uuid (first u))))

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
             (.put (decoder content)) (.rewind))
        hi (.getLong bb)
        lo (.getLong bb)
        ;; put the uuid version back in the high number and clip off
        ;; the last sixteen bits down four.
        hi-mod (bit-or (bit-and hi (bit-not 16rffff))
                       (bit-shift-left version 12)
                       (bit-shift-right (bit-and hi 16rffff) 4))
        ;; fix the last byte because this shit is confusing.
        lo-tmp (bit-or (bit-and lo (bit-not 16rff))
                       (bit-shift-left (bit-and lo 16rff)
                                       (if no-case 1 2)))
        ;; put the lowest four bits from hi at the top, then lo-tmp
        ;; shifted right (and clip off the damn high bits).
        lo-mod (bit-or
                (bit-shift-left hi 60)
                (bit-and (bit-shift-right lo-tmp 4)
                         (bit-not (bit-shift-left 16rf 60))))
        ]
    ;;(println (format "%x %x %x" hi-mod lo-tmp lo-mod))
    ;; and that's that
    (UUID. hi-mod lo-mod)))
