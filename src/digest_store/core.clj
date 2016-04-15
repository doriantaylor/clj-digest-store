(ns digest-store.core
  (:use [digest :only [Digestible]]
        [clojure.set :only [intersection difference]]
        [digest-store.utils]
        [clojure.java.io])
  (:require [pantomime.mime :as pm])
  (:import [java.security MessageDigest] [java.net URI]
           [java.util Arrays Date] [java.io InputStream File])
)

(def ^:const valid-digests
  "A set of supported digest algorithms, normalized to keywords."
  (let [x (intersection
           ;; currently there are a bunch of synonyms as strings
           (set (map #(keyword (.toLowerCase %)) (digest/algorithms)))
           ;; here are our normalized algorithm names
           #{:md5 :sha-1 :sha-256 :sha-384 :sha-512})]
        x))

(defn- sort-digest-size-then-lexical
  "Does what it says on the tin. Expects pairs like [:md5 16]."
  [a b]
  (let [f1 (first a) f2 (first b) s1 (second a) s2 (second b)]
    (or (< s1 s2) (and (= s1 s2) (< (compare f1 f2) 0)))))

(def ^:const digest-sizes
  "A sorted map of digest algorithms and their byte lengths."
  (into (array-map)
        (sort sort-digest-size-then-lexical
              (map #(vec [% (.getDigestLength
                             (MessageDigest/getInstance (name %)))])
                   valid-digests))))

(defprotocol DigestStore
  (store-add    [store item] "Add an item to the digest store.")
  (store-get    [store item] "Retrieve an item from the digest store.")
  (store-remove [store item]
    "Remove (but keep metadata for) an item in the digest store.")
  (store-forget [store item]
    "Remove an item from the digest store and erase its metadata.")
  (store-stats  [store] "Get statistics for the digest store.")
  (store-close  [store] "Close and release the digest store.")
)

(defmulti digest-store
  "Initialize a digest store."
  (fn [& args] (let [x (first args)] (if x x :default)))
  :default :fs-bdb)

;; this is an exact copy of signature in clj-digest, which is private :(
(defn- signature
  "Get signature (string) of digest."
  [^MessageDigest algorithm]
  (let [size (* 2 (.getDigestLength algorithm))
        sig (.toString (BigInteger. 1 (.digest algorithm)) 16)
        padding (apply str (repeat (- size (count sig)) "0"))]
    (str padding sig)))
;; XXX on second thought we don't use this anymore so can probably nuke it.

;; this little puppy generates all the digests at once and puts them in a map.
(extend-protocol Digestible
  java.util.Collection
  (-digest [message algorithm]
    (let [algos (into {} (map #(vec [(keyword %) ^MessageDigest
                                     (MessageDigest/getInstance (name %))])
                              (if (coll? algorithm) algorithm [algorithm])))]
      ;; make sure the digest contexts are fresh, though cargo-culty,
      ;; not sure why they wouldn't be (unless they're singletons?)
      (map #(.reset ^MessageDigest %) (vals algos))
      ;; do the work
      (doseq [^bytes b message]
        (doseq [a (vals algos)] (.update ^MessageDigest a b)))
      ;; return the result
      (if (and (not (coll? algorithm)) (= 1 (count algos)))
        ;; mimic original behaviour
        (as-uri (get algos (first (keys algos))))
        ;; new behaviour: hash map of algo:digest pairs
        (into {} (map #(vec [% (as-uri (get algos %))]) (keys algos))))))
)

(defprotocol StoreObjectProtocol
  (stream  [obj] "Retrieve the stream from the store object, if it exists.")
  (stream? [obj] "True if the store object contains a stream.")
  (metadata         [obj] "Get the store object's metadata all in one lump.")
  (digests [obj] "Retrieve a map of the digests for the store object")
  (digest  [obj algorithm]
    "Get the digest URI for the store object given the algorithm.")
  (byte-size        [obj] "Get the store object's size in bytes.")
  (mime-type        [obj] "Get the store object's MIME type.")
  (charset          [obj]
    "Get the store object's character set (if applicable, e.g. utf-8).")
  (language         [obj]
    "Get the store object's language (if applicable, e.g. en).")
  (encoding         [obj]
    "Get the object's lossless encoding (if applicable, e.g. gzip, base64).")
  (first-seen       [obj] "Get the first-seen time for the store object.")
  (last-inserted    [obj] "Get the last-inserted time for the store object.")
  (props-modified   [obj]
    "Get the property modification time for the store object.")
  (removed          [obj]
    "Get the time the object was removed from the store (if applicable).")
  (type-checked     [obj] "Get the type-checked flag from the store object.")
  (type-valid       [obj] "Get the type-valid flag from the store object.")
  (charset-checked  [obj] "Get the charset-checked flag from the store object.")
  (charset-valid    [obj] "Get the charset-valid flag from the store object.")
  (encoding-checked [obj]
    "Get the encoding-checked flag from the store object.")
  (encoding-valid   [obj] "Get the encoding-valid flag from the store object.")
  (syntax-checked   [obj] "Get the syntax-checked flag from the store object.")
  (syntax-valid     [obj] "Get the syntax-valid flag from the store object.")
)

(defrecord StoreObject
;    [^InputStream stream ^hash-map digests ^hash-map times ^hash-map flags]
    [stream digests attrs times flags]
  StoreObjectProtocol
  ;; the thing
  (stream           [obj]
    (let [f (:stream obj)
          s (if (fn? f) (f) f)]
      (assert (or (nil? s) (instance? InputStream s))
                  "Stream member not an InputStream") s))
  (stream?          [obj] (not (nil? stream)))
  ;; cryptographic digests of the thing
  (digests          [obj] digests)
  (digest           [obj algorithm] (get digests algorithm))
  ;; metadata about the thing
  (metadata         [obj]
    { :digests digests :attrs attrs :times times :flags flags })
  (byte-size        [obj] (:size      attrs))
  (mime-type        [obj] (:type      attrs))
  (charset          [obj] (:charset   attrs))
  (language         [obj] (:language  attrs))
  (encoding         [obj] (:encoding  attrs))
  ;; metadata about the thing pertaining to the digest store
  (first-seen       [obj] (:ctime times))
  (last-inserted    [obj] (:mtime times))
  (props-modified   [obj] (:ptime times))
  (removed          [obj] (:dtime times))
  ;; metadata pertaining to the heretofore-nonexistent checker process
  (type-checked     [obj] (:type-checked     flags))
  (type-valid       [obj] (:type-valid       flags))
  (charset-checked  [obj] (:charset-checked  flags))
  (charset-valid    [obj] (:charset-valid    flags))
  (encoding-checked [obj] (:encoding-checked flags))
  (encoding-valid   [obj] (:encoding-valid   flags))
  (syntax-checked   [obj] (:syntax-checked   flags))
  (syntax-valid     [obj] (:syntax-valid     flags))
)

(defn as-date
  "Coerces an integer into a java.util.Date, unless it's zero or nil, then nil.
  Does the 'right thing' vis-a-vis ints and longs."
  [x]
  (cond
    ;; noop
    (instance? Date x) x
    ;; positive integers/longs
    (and (integer? x) (pos? x)) (Date. (if (instance? Long x) x (* x 1000)))
                                        ;(if (<= x 16r7fffffff) (* x 1000) x))
    ;; zero or nil
    (or (nil? x) (zero? x)) nil
    :else (throw (IllegalArgumentException.
                  (str x " cannot be made into a Date")))))

(def ^:private valid-attrs #{:size :type :charset :language :encoding})
(def ^:private valid-times #{:ctime :mtime :ptime :dtime})
(def ^:private valid-flags #{:type-checked     :type-valid
                             :charset-checked  :charset-valid
                             :encoding-checked :encoding-valid
                             :syntax-checked   :syntax-valid})

(defn store-object
  "Create a new digest store object."
  ([] (store-object nil nil nil nil nil))
  ([stream] (store-object stream nil nil nil nil))
  ([stream digests] (store-object stream digests nil nil nil))
  ([stream digests attrs] (store-object stream digests attrs nil nil))
  ([stream digests attrs times] (store-object stream digests attrs times nil))
  ([stream digests attrs times flags]
  ;; check that the stream is an fn, InputStream or nil
  (when (not (or (nil? stream) (instance? InputStream stream) (fn? stream)))
    (throw (IllegalArgumentException.
            (str "stream must be nil, an input stream, "
                 "or an fn that returns an input stream."))))

  ;; check that the digests contain the right key-value pairs
  (when (not (or (nil? digests) (map? digests)))
    (throw (IllegalArgumentException. "digests must be nil or a map")))
  (when (not (or (empty? digests)
                 (empty? (difference (set (keys digests)) valid-digests))))
    (throw (IllegalArgumentException.
            (str "digests must be empty or contain valid digest keys: "
                 valid-digests))))
  (when (not (every? #(and (instance? java.net.URI %)
                           (= (.toLowerCase (.getScheme %)) "ni"))
                     (vals digests)))
    (throw (IllegalArgumentException.
            "digest values must be RFC6920 ni: URIs")))

  ;; check that the attrs have the correct keys
  (when (not (or (nil? attrs) (map? attrs)))
    (throw (IllegalArgumentException. "attrs must be nil or a map")))
  (when (not (or (empty? attrs)
                 (empty? (difference (set (keys attrs)) valid-attrs))))
    (throw (IllegalArgumentException.
            (str "attrs must only contain: " valid-attrs))))

  ;; check that the times are java.util.Date or coerce (0 is nil)
  (when (not (or (nil? times) (integer? times)
                 (instance? Date times) (map? times)))
    (throw (IllegalArgumentException.
            "times must be nil, an integer, a Date object, or a map")))
  (when (map? times)
    (when (not (or (empty? times)
                   (empty? (difference (set (keys times)) valid-times))))
      (throw (IllegalArgumentException.
              (str "times must only contain: " valid-times))))
    (when (not (every? #(or (nil? %) (integer? %) (instance? Date %))
                       (vals times)))
      (throw (IllegalArgumentException.
              "times must be nil, non-negative integers, or Date objects"))))

  ;; check that the flags are all there or supplant with defaults
  (when (not (or (nil? flags) (map? flags)))
    (throw (IllegalArgumentException. "flags must be nil or a map")))
  (when (not (or (empty? flags)
                 (empty? (difference (set (keys flags)) valid-flags))))
    (throw (IllegalArgumentException.
            (str "flags must only contain " valid-flags))))

  ;; and now the constructor :P
  (let [s stream
        d (into {} digests) ; noop for now
        a (into {} attrs)   ; noop for now
        ;; this mofo will let you put a date or unix timestamp (int
        ;; for no milliseconds, long for yes milliseconds) in and it
        ;; will generate the ctime, mtime, and ptime, but no dtime
        t (if (or (nil? times) (integer? times) (instance? Date times))
            (let [x (or (as-date times) (Date.))]
              (into {} (map #(vec [% x]) [:ctime :mtime :ptime])))
            (into {} (map #(vec [% (as-date (get times %))]) (keys times))))
        ;; generate flags (which should all be false anyway)
        f (merge (into {} (map #(vec [% false]) valid-flags)) flags)]
    (assert (not (and stream (:dtime t)))
            "Can't have both a stream and a deletion time.")
    (->StoreObject s d a t f))))

(defprotocol StoreObjectCoercions
  (as-store-object [obj] "Turn a thing into a StoreObject"))

(extend-protocol StoreObjectCoercions
  StoreObject
  (as-store-object [obj] obj)
  InputStream
  (as-store-object [stream] (store-object stream))
  File
  (as-store-object [^File file]
    (assert (.exists file) (str file " does not exist"))
    (assert (.canRead file) (str file " is not readable"))
    (let [size (.length file)
          type (pm/mime-type-of file)
          mtime (.lastModified file)]
    (store-object #(input-stream file) nil {:size size :type type} mtime)))
  URI
  (as-store-object [^URI uri]
    (when (not (ni-uri? uri))
      (throw (IllegalArgumentException. (str uri " not a ni: URI"))))
    (let [algorithm (keyword (ni-uri-algorithm uri))]
      (when (not (contains? valid-digests algorithm))
        (throw (IllegalArgumentException.
                (str algorithm " in " uri " is not a recognized algorithm"))))
      (store-object nil { algorithm uri })))
  java.util.Map
  (as-store-object [m]
    (when (not (every? #(contains? valid-digests %) (keys m)))
      (throw (IllegalArgumentException.
              (str "Map must contain only valid digests: " valid-digests))))
    (when (not (every? #(and (instance? URI %) (ni-uri? %)) (vals m)))
      (throw (IllegalArgumentException. "All values must be ni: URIs")))
    (store-object nil m))
)
