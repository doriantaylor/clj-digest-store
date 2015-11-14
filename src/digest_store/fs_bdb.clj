(ns digest-store.fs-bdb
  "Filesystem/Berkeley DB-based driver for digest store"
  (:use cupboard.bdb.je 
        [clojure.string :only [split]]
        [digest-store.core :only [DigestStore digest-store]])
  (:require [clojure.java.io :as io])
  (:import [org.apache.commons.codec.binary Base32 Base64 Hex]
           [java.net URI URL]
           [java.util UUID]
           [java.security MessageDigest])
)

(defrecord FSBDBDigestStore [conf env control entries]
  DigestStore
  (close [store]
    (map db-close (cons control (map #(get entries %) (keys entries))))
    (db-env-close env))
  ;; (add [store rec])
  ;; (get [store rec])
  ;; (remove [store rec])
  ;; (forget [store rec])
  ;; (stats [store])
)

(defmethod digest-store :fs-bdb [& conf-args]
  "Create and open a filesystem/Berkeley DB-based digest store."
  (let [defaults {:dir "/tmp/digest-store"
                  :algorithms #{:md5 :sha-1 :sha-256 :sha-384 :sha-512}
                  :primary :sha-256 }
        conf (let [c (if (nil? conf-args) defaults (merge defaults conf-args))
                   d (io/as-file (:dir c))] (.mkdirs d) (assoc c :dir d))
        -dbconf { :transactional true :allow-create true }
        env (db-env-open (:dir conf) -dbconf)
        control (db-open env "control" -dbconf)
        entries (into {} (map #(vec [% (db-open env (name %) -dbconf)])
                              (:algorithms conf)))
        ]
    ;; now we check against 
    (with-db-txn [txn env]
      (let [primary (db-get "primary" :txn txn)
            
            ]
        
        (if (empty? (db-get "primary" :txn))
          nil
          )))
    ;; make sure the dir is there
    (FSBDBDigestStore. conf env control entries)
))
  
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

