(ns digest-store.fs-bdb
  "Filesystem/Berkeley DB-based driver for digest store"
  (:use cupboard.bdb.je digest-store.core digest-store.utils
        [clojure.string :only [split trim]]
        [clojure.set :only [intersection]]
        [digest-store.core :only
         [DigestStore digest-store valid-digests digest-sizes as-date]])
        
  (:require digest
            [clojure.java.io :as io]
            [byte-streams :as bs]
            [gloss.core :as g]
            [gloss.io :as gio]
            [pantomime.mime :as pm])
  (:import [java.util Date Arrays]
           [java.nio ByteBuffer]
           [java.io File InputStream OutputStream FileNotFoundException])
)

(defn- tee-streams
  "Return a byte array from an input stream while writing it to an
  output stream."
  [^InputStream in ^OutputStream out buffer-size]
  (let [^bytes buffer (byte-array buffer-size)
        size (.read in buffer)]
    (when (> size 0)
      (let [b (if (= size buffer-size) buffer
                  (Arrays/copyOf buffer size))]
        (.write ^OutputStream out b)
        b))))

(defn- tee-seq
  "Produce a lazy sequence of byte arrays, suitable for message digest
  processing, while at the same time writing to an output stream."
  [^InputStream in ^OutputStream out size]
  (take-while (complement nil?) (repeatedly #(tee-streams in out size))))

(defn- store-locate
  "Locate the file in the store. Assumes uri represents the primary digest."
  [store uri]
  (let [base (:dir (:conf store))
        target-slug (-> (ni-uri-digest uri) (hex-decode) (base32-encode))]
    ;; maybe more readable? subs fails with a null pointer exception
    ;; if the upper bound is nil
    (io/file base (map #(apply (partial subs target-slug) %)
                       [[0 4] [4 8] [8 12] [12]]))))
;;    (io/file base (subs target-slug 0 4) (subs target-slug 4 8)
;;             (subs target-slug 8 12) (subs target-slug 12))))


;(defmulti ^:private fs-bdb-store-add 
;  (fn [store item] (type item)))

;(defmethod fs-bdb-store-add Sto

(defn- all-parents [^File file]
  "Get all the parents of a file. Surprised this doesn't already exist."
  (loop [f file out []]
    (let [p (.getParent f)]
      (if (nil? p) out 
          ;; fyi conj works differently whether it's a list or vector
          (recur (io/as-file p) (conj out (io/as-file p)))))))

;;;; private store ops

(def ^:private metadata-codec
  (g/ordered-map
   :times (g/ordered-map
           :ctime :uint32-be
           :mtime :uint32-be
           :ptime :uint32-be
           :dtime :uint32-be)
   :flags (g/bit-map
           :type-checked     1
           :type-valid       1
           :charset-checked  1
           :charset-valid    1
           :encoding-checked 1
           :encoding-valid   1
           :syntax-checked   1
           :syntax-valid     1)
   :attrs (g/ordered-map
           :type     (g/string :us-ascii :delimiters [(char 0)])
           :language (g/string :us-ascii :delimiters [(char 0)])
           :charset  (g/string :us-ascii :delimiters [(char 0)])
           :encoding (g/string :us-ascii :delimiters [(char 0)]))
))

(defn- required-algos
  "Get the ordered list of digest algorithms minus the primary"
  [algorithms primary]
  (vec (filter #(and (contains? algorithms %) (not= % primary))
                     (keys digest-sizes))))

(defn encode-metadata
  "Encode the object's metadata into a byte array. Needs to know the
  set of agorithms in the store and which is the primary one. "
  [obj algorithms primary]
  (let [;; this needs to be in the right order
        reqd    (required-algos algorithms primary)
        obj-has (intersection (set (keys (digests obj))) (set reqd))
        digests (do
                  (when (not= (set reqd) obj-has)
                    (throw (IllegalArgumentException.
                            (str "StoreObject needs these algorithms: "
                                 reqd " has " obj-has))))
                  (map
                        #(hex-decode (ni-uri-digest (digest obj %))) reqd))
        times (let [x (:times obj)]
                (into {} (map #(vec
                                [% (or (and (get x %)
                                            (quot (.getTime ^Date (get x %))
                                                  1000)) 0)])
                              [:ctime :mtime :ptime :dtime])))
        metadata (bs/to-byte-array
                  (gio/encode metadata-codec
                              {:times times
                               :flags (:flags obj)
                               :attrs (into
                                       {}
                                       (map
                                        #(vec [% (or (get (:attrs obj) %)"")])
                                        [:type :charset :language :encoding]))
                               }))]

    ;;(println (apply + (map alength digests)))
    ;;(bs/print-bytes (bs/to-byte-array digests))
    ;;(bs/print-bytes metadata)
    (bs/to-byte-array (concat digests [metadata]))))

(defn decode-metadata
  [data algorithms primary]
  (let [algos (required-algos algorithms primary)
        ;; generate a map of byte arrays
        ba (into {} (map #(vec [% (byte-array (get digest-sizes %))]) algos))
        ^ByteBuffer bb (bs/to-byte-buffer data)
        digests (do
                  ;; snarf up the data first
                  (doseq [x (map #(get ba %) algos)] (.get bb x))
                  ;; now generate the URIs
                  (into {} (map #(vec [%
                                       (as-uri
                                        (str "ni:///" (name %) ";"
                                             (base64-encode (get ba %)
                                                            true)))]) algos)))
        ;; gloss resets the byte buffer so we need to chop it off
        ;; or who knows, maybe i did. anyway it's sketchy.
        ^ByteBuffer mdb (bs/to-byte-buffer (bs/to-byte-array bb))
        metadata (try
                   (gio/decode metadata-codec mdb)
                   (catch Exception e
                     (bs/print-bytes mdb)
                     (throw e)))
        ]
    ;;(println digests)
    {:digests digests
     ;; get rid of the empty strings
     :attrs (into {} (filter #(not= "" (second %))
                             (into [] (:attrs metadata))))
     ;; might as well deal with the timestamps here
     :times (into {} (map #(vec [(first %) (as-date (int (second %)))])
                          (into [] (:times metadata))))
     :flags (:flags metadata)
     }))

(defn- set-metadata
  "Sets all the metadata for a new record. Throws an exception unless
  the StoreObject is complete."
  [store obj]
  ;; (let [env (:env store)
  ;;       algorithms nil]



  ;;   (with-db-txn [txn env]
  ;;     (doseq []
  ;;     )))
)

(defn- fs-bdb-store-get [store obj]
  ;; first get metadata


  ;; then locate file
)

(defn- fs-bdb-store-add [store item]
  ;; 
  (let [conf (:conf store)
        obj (as-store-object item)
        ^File temp (File/createTempFile
                    "blob" "" (io/file (:dir conf) "tmp"))]
    (assert (stream? obj) "Can't add an object with no stream!")
    (try
      (let [digests (with-open [in (stream obj) out (io/output-stream temp)]
                      (digest/digest (:algorithms conf)
                                     (tee-seq in out 16r10000)))
            size (.length temp)
            mime-type (pm/mime-type-of temp)
            target-slug (-> (get digests (:primary conf))
                            (ni-uri-digest) (hex-decode) (base32-encode))
            ^File target-file (io/file (:dir conf) (subs target-slug 0 4)
                                       (subs target-slug 4 8)
                                       (subs target-slug 8 12)
                                       (subs target-slug 12))
            parents (take-while #(not= % (:dir conf))
                                (all-parents target-file))]
        ;; do the temp file's permissions
        (.setWritable temp false false)
        (.setReadable temp false false)
        (.setReadable temp true  true)
        ;; now do the dirs

        ;; XXX this shit is totally asking for it. race condition.
        ;; actually i slept on it and each dir has literally a one
        ;; in a million chance (2^20) of being written into *ever*,
        ;; let alone written and read at the exact same time. there
        ;; are 60 bits of entropy in all three hashed dirs, so like
        ;; over 10^18, or a quintillion positions.

        (when (io/make-parents target-file)
          (println (str "made " (.getParent target-file)))
          (doseq [^File p parents]
            (.setExecutable p false false)
            (.setExecutable p true  true)
            (.setWritable   p false false)
            (.setWritable   p true  true)
            (.setReadable   p false false)
            (.setReadable   p true  true)))
        ;; do some checking on this, apparently java doesn't
          ;; raise an exception if this fails.
        (when (not (.renameTo temp target-file))
          (throw (FileNotFoundException.
                  (str "Could not rename " temp " to " target-file))))
        ;;(println (.renameTo temp target-file))
        ;;(println parents)
        (store-object #(io/input-stream target-file)
                      digests {:size size :type mime-type }))
      (catch Exception e (throw e))
      (finally
        (.delete temp)))))

(defrecord FSBDBDigestStore [conf env control entries]
  DigestStore
  (store-add [store item] (fs-bdb-store-add store (as-store-object item)))
  (store-get [store item] (fs-bdb-store-get store (as-store-object item)))
  ;; (store-remove [store rec])
  ;; (store-forget [store rec])
  ;; (store-stats [store])
  (store-close [store]
    (doseq [db (cons control (vals entries))]
      ;;(if (not (nil? (:val db))) (db-close db))
      (db-close db)
      ;;(println db) 
      )
    (db-env-checkpoint env)
    (db-env-clean-log env)
    (db-env-close env))
    ;; (if (not (nil? (:val env))) (db-env-close env)))
)


(defn conf-from-control
  "Get the relevant configuration items from the control database."
  [control]
  (let [[_ algorithms] (db-get control "algorithms")
        [_ primary] (db-get control "primary")]
    { :algorithms (if algorithms
                    (set (map keyword (split (trim algorithms) #"\s*,+\s*")))
                    #{})
      :primary (when primary (keyword primary)) }))

(defn env-for-db [db]
  (let [e (.getEnvironment @(:db-handle db))]
    (when e (struct cupboard.bdb.je/db-env
                    (.getHome e)
                    (.. e (getConfig) (getTransactional))
                    (atom e)))))

(defn store-timestamp [db key & val]
  (let [date (or (first val) (Date.))]
    (with-db-txn [txn (env-for-db db)]
      (db-put db key (quot (.getTime date) 1000) :txn txn))))

(defn get-timestamp [db key]
  (let [[_ ts] (db-get db key)]
    (when (integer? ts) (Date. (* ts 1000)))))

;(defn init-control [ds]


(defmethod digest-store :fs-bdb [& conf-args]
  "Create and open a filesystem/Berkeley DB-based digest store."
  (let [defaults {:dir "/tmp/digest-store"
                  :algorithms #{:md5 :sha-1 :sha-256 :sha-384 :sha-512}
                  :primary :sha-256 }
        conf (let [c (if (nil? conf-args) defaults (merge defaults conf-args))
                   d (io/as-file (:dir c))] (.mkdirs d) (assoc c :dir d))
        dbconf { :transactional true :allow-create true }
        env (db-env-open (:dir conf) dbconf)
        control (db-open env "control" dbconf)
        entries (into {} (map #(vec [% (db-open env (name %) dbconf)])
                              (:algorithms conf)))
        ]
    (.mkdir (io/file (:dir conf) "tmp"))
    (with-db-txn [txn env]
      (db-put control "primary" (name (:primary conf)) :txn txn)
      )
    ;; Verify the contents of the control database against the
    ;; supplied arguments. Otherwise inititalize control
    ;; database. 

    ;; now we check against 
    ;; (with-db-txn [txn env]
    ;;   (let [primary (db-get "primary" :txn txn)
            
    ;;         ]
        
    ;;     (if (empty? (db-get "primary" :txn))
    ;;       nil
    ;;       )))
    ;; make sure the dir is there
    (FSBDBDigestStore. conf env control entries)
))

;; (defmulti ^:private fs-bdb-store-add
;;   (fn [_ item] (type item)))

;; (defmethod ^:private fs-bdb-store-add digest_store.core.StoreObject [store item]
;; ) 

;; (defmethod ^:private fs-bdb-store-add InputStream [store item]
;; )
