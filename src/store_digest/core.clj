(ns store-digest.core
  (:use [digest] [cupboard.bdb.je] [clojure.java.io])
  (:import [java.security MessageDigest])
)

;;(defrecord DigestStore [])

(defn- signature
  "Get signature (string) of digest."
  [^MessageDigest algorithm]
  (let [size (* 2 (.getDigestLength algorithm))
        sig (.toString (BigInteger. 1 (.digest algorithm)) 16)
        padding (apply str (repeat (- size (count sig)) "0"))]
    (str padding sig)))

(extend-protocol Digestible
  java.util.Collection
  (-digest [message algorithm]
    (if (coll? algorithm)
      (let [algos (into {} (map #(vec [% ^MessageDigest
                                       (MessageDigest/getInstance %)]
                                      ) algorithm))]
        (map #(.reset (get algos %)) (keys algos))
        (doseq [^bytes b message]
          (doseq [a (map #(get algos %) (keys algos))] (.update a b)))
        (into {} (map #(vec [% (signature (get algos %))]) (keys algos))))
      (let [^MessageDigest algo (MessageDigest/getInstance algorithm)]
        (.reset algo)
        (doseq [^bytes b message] (.update algo b))
        (signature algo))))
)

;;(defn store-open [dir]
;;  "Returns a digest store")

