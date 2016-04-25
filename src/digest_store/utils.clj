(ns digest-store.utils
  (:use [clojure.string :only [split]])
  (:require [pantomime.mime :as pm])
  (:import [org.apache.commons.codec.binary Base32 Base64 Hex]
           [org.apache.tika.mime MimeType MediaType]
           [java.net URI URL]
           [java.util UUID]
           [java.nio ByteBuffer]
           [java.security MessageDigest])
)

;; base64 stuff

(defmulti base64-encode
  "Turn a string or byte array into a Base64 string."
  (fn [s & url-safe] (type s)))

(defmethod base64-encode (Class/forName "[B") [b & url-safe]
  (first (split (String. (.encode
                          (Base64. 0 (byte-array 0) 
                                   (boolean (first url-safe))) b)) #"=")))

(defmethod base64-encode String [s & url-safe]
  (base64-encode (.getBytes s) (first url-safe)))

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
    (if (first upper-case) (.toUpperCase s) (.toLowerCase s))))

(defmethod hex-encode String [s & upper-case]
  (hex-encode (.getBytes s) (first upper-case)))

(defn hex-decode
  "Turn a hexadecimal string into a decoded byte array."
  [s] (.decode (Hex.) s))

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
    (as-uri
     (str "ni:///" (.getAlgorithm m) ";" (base64-encode (.digest m) true))))
  )

(defn ni-uri? [^URI uri]
  (= (.toLowerCase (.getScheme uri)) "ni"))

(defn ni-uri-split [uri]
  (let [[_ algo digest] (re-find #"^/*([^;]+);+(.*?)$" (.getPath (as-uri uri)))]
    [(keyword (.toLowerCase algo)) (-> digest (base64-decode) (hex-encode))] ))

(defn ni-uri-algorithm
  "Retrieve the algorithm string in an ni: URI"
  [uri]
  (first (ni-uri-split (as-uri uri))))

(defn ni-uri-digest
  "Retrieve the (hexadecimal) digest from an ni: URI"
  [uri]
  (second (ni-uri-split (as-uri uri))))

;; uuid stuff

(defmulti uuid
  "Create a UUID object from a string or URI, or generate a random one."
  (fn
    ([x] (type x))
    ([] :default)))

;;  "Make a UUID from a string."
(defmethod uuid
  String [s] (UUID/fromString s))

;;  "Make a UUID from a urn:uuid URI object."
(defmethod uuid
  URI [u] (let [[_ s] (re-find #"^(?i:urn:uuid:)([0-9A-Fa-f-]+)$"
                               (.toString u))]
            (if (nil? s) (throw (IllegalArgumentException.
                                 (str u " not a urn:uuid")))
                (uuid s))))

;; noop method
(defmethod uuid UUID [u] u)

;; empty 
(defmethod uuid
  :default [] (. UUID randomUUID))

;; blank
(defmethod uuid
  nil [_] (uuid))

(defn uuid-urn
  "Make a urn:uuid:..."
  [& u]
  (println u)
  (as-uri (uuid (first u))))

;;;; UUID-NCName conversion algorithm:

;;;; 1) Get a binary representation of the UUID.
;;;; 2) Pull out the version nybble (4 bits at bit 48)
;;;; 3) Shift all subsequent bits 4 to the left.
;;;; 4) Shift the last byte right, 1 bit for Base32, 2 for Base64.
;;;; 5) Encode in either Base32 (case-insensitive) or Base64.
;;;; 6) Truncate the last character (always 0) and remove "=" padding.
;;;; 7) Encode the version nybble as a letter (A-P) and put it in front.

;;;; Do this in reverse to decode the UUID.

;;;; The purpose of putting the version nybble at the front is to
;;;; guarantee that the resulting string is a valid NCName. This value
;;;; is always case-insensitive (at least insofar as decoding is
;;;; concerned), as it maps 4 bits to the first 16 letters of the
;;;; alphabet. URL-safe Base64 encoding is suitable for XML IDs and
;;;; RDF blank nodes, as well as Clojure symbols and keywords. Base32,
;;;; being naturally case-insensitive and containing only alphanumeric
;;;; characters, is suitable for generated identifiers in languages
;;;; that do not permit (e.g.) hyphens, though its representation will
;;;; be slightly longer.

;;;; The purpose of shifting the last byte is to ensure that it fits
;;;; into the encoding alphabet. After the version nybble is removed,
;;;; there are 124 bits of information in the UUID (well, 122, but
;;;; let's not split hairs). However, the first 15 bytes (120 bits)
;;;; are encoded cleanly by both schemes, as 15*8 = 20*6 = 24*5 =
;;;; 120. This leaves us with the last 5 or 6 bits to deal with. The
;;;; encoding schemes take the high bits first, so by moving the
;;;; remaining four bits down one for Base32 and two for Base64 will
;;;; guarantee that the remaining bits occupy the lowest values in
;;;; their respective encoding alphabets.

;;;; The implementation in org.apache.commons.codec.binary appears
;;;; to pad incomplete bytes when encoding, and truncate them
;;;; when decoding. This will put an "A" (ordinal 0) at the end of the
;;;; encoded sequence, and if that terminating "A" is missing when
;;;; decoding, it will discard the last symbol. So we take it off when
;;;; encoding, because it contains no information, but we have to put
;;;; it back on when we decode the string.

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
        ;; fix the last byte first because this shit is confusing.
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

;; XXX all of this should be in pantomime

;; XXX PS why the ƒ are there two different, incompatible, non-related
;; classes in Tika (MimeType/MediaType)?

(def ^:private TYPE-REGISTRY (.getMediaTypeRegistry pm/registry))

(defprotocol MimeTypeCoercions
  (as-mime-type  [x] "Turn whatever into a MimeType")
  (as-media-type [x] "Turn whatever into a MediaType")
)

(extend-protocol MimeTypeCoercions
  String
  (as-mime-type  [^String x] (try (pm/for-name x)))
  (as-media-type [^String x] (try (.getType (as-mime-type x))))
  MimeType
  (as-mime-type  [^MimeType x] x)
  (as-media-type [^MimeType x] (.getType x))
  MediaType
  (as-mime-type  [^MediaType x] (.toString (.getBaseType x)))
  (as-media-type [^MediaType x] x)
)

(defn mime-type-isa [a b]
  (let [^MediaType ta (as-media-type a)
        ^MediaType tb (as-media-type b)]
    (.isInstanceOf TYPE-REGISTRY ta tb)))
