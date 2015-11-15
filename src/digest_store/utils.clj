(ns digest-store.utils
  (:use [clojure.string :only [split]])
  (:import [org.apache.commons.codec.binary Base32 Base64 Hex]
           [java.net URI URL]
           [java.util UUID]
           [java.security MessageDigest])
)

(defn base32-encode [str]
  "Encode a base32 string"
  ;; Base32 constructor with an argument of 0 means no line separator
  (first (split (.toLowerCase
                 (String. (.encode (Base32. 0) (.getBytes str)))) #"=")))

(defn base32-decode [str]
  "Decode a base32 string into uh, something?"
  (.decode (Base32.) (.toUpperCase str)))

(defn base32-to-hex-string [str]
  (String. (.encode (Hex.) (base32-decode str))))

(defprotocol URICoercions
  (as-uri [x] "Coerce the thing to a URI"))

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

