(ns store-digest.core
  (:use [digest]
        [cupboard.bdb.je]
        [clojure.java.io])
  (:require [pantomime.mime :as pm])
  (:import [java.security MessageDigest])
)

(defprotocol DigestStore
  (add [store rec])
  (get [store rec])
  (remove [store rec])
  (forget [store rec])
  (stats [store])
  (close [store])
)

(defmulti digest-store
  (fn [& args]
    (if (and args (first args))
      (let [x (first args)]
        x)))
  :default :fs-bdb)

;; this is an exact copy of signature in clj-digest, which is private :(
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
    (let [algos (into {} (map #(vec [(keyword %) ^MessageDigest
                                     (MessageDigest/getInstance (name %))])
                              (if (coll? algorithm) algorithm [algorithm])))]
      ;; make sure the digest contexts are fresh, though cargo-culty,
      ;; not sure why they wouldn't be (unless they're singletons?)
      (map #(.reset (get algos %)) (keys algos))
      ;; do the work
      (doseq [^bytes b message]
        (doseq [a (map #(get algos %) (keys algos))] (.update a b)))
      ;; return the result
      (if (and (not (coll? algorithm)) (= 1 (count algos)))
        ;; mimic original behaviour
        (signature (get algos (first (keys algos))))
        ;; new behaviour: hash map of algo:digest pairs
        (into {} (map #(vec [% (signature (get algos %))]) (keys algos))))))
)

;;(defn store-open [dir]
;;  "Returns a digest store")

