(ns digest-store.fs-bdb
  "Filesystem/Berkeley DB-based driver for digest store"
  (:use cupboard.bdb.je digest-store.core digest-store.utils
        [clojure.string :only [split trim join]]
        [clojure.set :only [intersection subset?]]
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

(def STORE_DIR "store")
(def TEMP_DIR  "tmp")

;; 

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
    (io/file base STORE_DIR (map #(apply (partial subs target-slug) %)
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

(defn- encode-metadata
  "Encode the object's metadata into a byte array. Needs to know the
  set of agorithms in the store and which is the primary one. "
  [data algorithms primary]
  (let [;; this needs to be in the right order
        reqd     (required-algos algorithms primary)
        data-has (intersection (set (keys (:digests data))) (set reqd))
        digests (do
                  (when (not= (set reqd) data-has)
                    (throw (IllegalArgumentException.
                            (str "Metadata needs these algorithms: "
                                 reqd " has " data-has))))
                  (map #(hex-decode (ni-uri-digest (-> data :digests %))) reqd))
        times (let [x (:times data)]
                (into {} (map #(vec
                                [% (or (and (get x %)
                                            (quot (.getTime ^Date (get x %))
                                                  1000)) 0)])
                              [:ctime :mtime :ptime :dtime])))
        metadata (bs/to-byte-array
                  (gio/encode metadata-codec
                              {:times times
                               :flags (:flags data)
                               :attrs (into
                                       {}
                                       (map
                                        #(vec [% (or (get (:attrs data) %)"")])
                                        [:type :charset :language :encoding]))
                               }))]

    ;;(println (apply + (map alength digests)))
    ;;(bs/print-bytes (bs/to-byte-array digests))
    ;;(bs/print-bytes metadata)
    (bs/to-byte-array (concat digests [metadata]))))

(defn- decode-metadata
  [key data algorithms primary]
  ;; pop the primary algo out and prepend it
  (let [algos (cons primary (required-algos algorithms primary))
        ;; generate a map of byte arrays
        ba (into { primary key }
                 (map #(vec [% (byte-array (get digest-sizes %))])
                      (rest algos)))
        ^ByteBuffer bb (bs/to-byte-buffer data)
        digests (do
                  ;; snarf up the data first
                  (doseq [x (map #(get ba %) (rest algos))] (.get bb x))
                  ;; now generate the URIs for the whole set
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

;; all of this crap is for normalizing the input 

;; this thing should really take a bunch of different forms of digest:

;; 1: ni: URI as string
;; 2: ni: URI as object
;; 3: a set of ni: URIs (either string or object)
;; 4: a map of ni: URIs (where the keys are the algos)
;; 5: a seq-like thing of all of the above

;; normalize to a seq of maps of ni: URI objects

(defn- uri-pair-xf [f]
  (fn
    ([] (f))
    ([result] (f result))
    ([result input]
     (f result
        (let [uri (as-uri input)]
          [(keyword (ni-uri-algorithm uri)) uri])))))

(defn- coerce-to-digest-map [x]
  (cond (set? x) (into {} uri-pair-xf x)
        (map? x) (into {} (map #(vec [(first %) (as-uri (second %))])) x)
        :else (let [y (as-uri x)] { (keyword (ni-uri-algorithm y)) y } )))

(defn- coerce-to-digest-maps [x]
  (if (and (coll? x) (not (or (set? x) (map? x))))
    (map coerce-to-digest-map x)
    (list (coerce-to-digest-map x))))

(defn- best-digest
  [store digests]
  (let [conf (:conf store)
        { :keys [primary algorithms] } conf
        x (cons primary (reverse (required-algos algorithms primary)))]
    ;; gives us the "best" digest URI
    (first (map #(get digests %) x))))

(defn- store-do-something-with-metadata
  ([store digest-map]
   (with-db-txn [txn (:env store)]
     (store-do-something-with-metadata store digest-map txn)))
  ([store digest-map txn]

   )
  )

(defn- db-get-multi
  "Encapsulate a multi-record "
  [db key & opts-args]
  (with-db-cursor [cur db]
  )
)

(defn- store-get-metadata
  "Given the store, and one or more digest URIs, sets or maps thereof,
  or list/seq of those, return a list of"
  [store arg]
  (let [primary (-> store :conf :primary)
        entries (:entries store)
        algos (-> store :conf :algorithms)
        digest-list (coerce-to-digest-maps arg)]
    (with-db-txn [txn (:env store)]
      (remove nil? 
              (for [digests digest-list :let [uri (best-digest store digests)]]
                ;; fetch the entry specified by the URI, and
                ;; subsequently the main entry if the URI was not a
                ;; primary hash
                (let [algo (keyword (ni-uri-algorithm uri))
                      key (hex-decode (ni-uri-digest uri))
                      [_ entry1] (db-get (get entries algo) key :txn txn)
                      [_ entry2] (when (and entry1 (not= primary algo))
                                   (db-get (get entries primary) entry1
                                           :txn txn))
                      entry (or entry2 entry1)]
                  ;; then all we have to do is decode the content
                  (when entry
                    (decode-metadata key entry algos primary))))))))

(defn- store-put-metadata
  "Puts the metadata for a record into the database."
  ([store metadata]
   (with-db-txn [txn (:env store)]
     (store-put-metadata store metadata txn)))
  ([store metadata txn]
   (assert (= (-> store :conf :algorithms) (set (keys (:digests metadata))))
           "Metadata must contain all digest algorithms!")
   (let [primary (-> store :conf :primary)
         canon (hex-decode (ni-uri-digest (-> metadata :digests primary)))]
     ;; do the primary database
     (db-put (-> store :entries primary) canon
             (encode-metadata metadata
                              (-> store :conf :algorithms) primary) :txn txn)
     ;; now do the rest of them
     (doseq [other (required-algos (:digests metadata) primary)]
       (db-put (-> store :entries other)
               (hex-decode (ni-uri-digest (-> metadata :digests other)))
               canon :txn txn))
     ;; iunno, return something?
     true)))

(defn- fs-bdb-store-get [store obj]
  ;; first get metadata


  ;; then locate file
)

(defn- fs-bdb-store-add [store item]
  ;; 
  (let [conf (:conf store)
        obj (as-store-object item)
        ^File temp (File/createTempFile
                    "blob" "" (io/file (:dir conf) TEMP_DIR))]
    (try
      (assert (stream? obj) "Can't add an object with no stream!")
      (let [digests (with-open [in (stream obj) out (io/output-stream temp)]
                      (digest/digest (:algorithms conf)
                                     (tee-seq in out 16r10000)))
            size (.length temp)
            mime-type (pm/mime-type-of temp)
            target-slug (-> (get digests (:primary conf))
                            (ni-uri-digest) (hex-decode) (base32-encode))
            ^File target-file (io/file (:dir conf) STORE_DIR
                                       (subs target-slug 0 4)
                                       (subs target-slug 4 8)
                                       (subs target-slug 8 12)
                                       (subs target-slug 12))
            parents (take-while #(not= % (:dir conf))
                                (all-parents target-file))]

        ;; deal with the file
        (if (.exists target-file)
          (.delete temp)
          (do
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
              ;;(println (str "made " (.getParent target-file)))
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
                      (str "Could not rename " temp " to " target-file))))))
        ;; now deal with the metadata
        (let [m-in (metadata obj)
              m-out (merge m-in
                           { :digests digests
                            :attrs (merge
                                    (:attrs m-in)
                                    { :size size :type mime-type }) }) ]
          (store-put-metadata store m-out))
         
        ;; return a 'new' store object
        (store-object #(io/input-stream target-file)
                      digests { :size size :type mime-type }))

        ;; XXX do something more sophisticated with the error here
        (catch Exception e (throw e))
        (finally
          (.delete temp)))))

(defn- fs-bdb-store-remove
  ([store obj] (fs-bdb-store-remove store obj false))
  ([store obj forget]
   )
)

(defn- fs-bdb-store-stats [store]
)

(defn- fs-bdb-store-close [store]
  (let [{ :keys [env control entries] } store]
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

(defrecord FSBDBDigestStore [conf env control entries]
  DigestStore
  (store-add [store x] (fs-bdb-store-add store (as-store-object x)))
  (store-get [store x] (fs-bdb-store-get store (as-store-object x)))
  (store-remove [store x] (fs-bdb-store-remove store (as-store-object x)))
  (store-forget [store x] (fs-bdb-store-remove store (as-store-object x) true))
  (store-stats [store] (fs-bdb-store-stats store))
  (store-close [store] (fs-bdb-store-close store))
)


;; (defn conf-from-control
;;   "Get the relevant configuration items from the control database."
;;   [control]
;;   (let [[_ algorithms] (db-get control "algorithms")
;;         [_ primary] (db-get control "primary")]
;;     { :algorithms (if algorithms
;;                     (set (map keyword (split (trim algorithms) #"\s*,+\s*")))
;;                     #{})
;;       :primary (when primary (keyword primary)) }))

;; cribbed from cupboard.bdb.je
(defn- env-for-db [db]
  (let [e (.getEnvironment @(:db-handle db))]
    (when e (struct cupboard.bdb.je/db-env
                    (.getHome e)
                    (.. e (getConfig) (getTransactional))
                    (atom e)))))

(defn store-timestamp [db key & val]
  "Store a UNIX timestamp in a Berkeley DB key as a string."
  (let [date (or (first val) (Date.))]
    (with-db-txn [txn (env-for-db db)]
      (db-put db (name key) (str (quot (.getTime date) 1000)) :txn txn))))

(defn get-timestamp [db key]
  "Retrieve a UNIX timestamp (as a string) from a Berkeley DB key."
  (let [[_ ts] (db-get db (name key))]
    ;; XXX of course this will throw if the data in the db is bad
    (when (not (nil? ts))
      (Date. (* (Integer/parseInt ts) 1000)))))

(defn- inc-db-int
  ([db key val]
   (with-db-txn [txn (env-for-db db)]
     (inc-db-int db key val txn)))
  ([db key val txn]
   (when-not (= 0 val)
     (let [k (name key)
           [_ v] (db-get db k :txn txn)
           x (Integer/parseInt (or v "0"))
           y (+ x val)]
       (db-put db k (str y) :txn txn)
       y))))

;; initialization of digest store

(def ^:private DEFAULTS {:dir (io/as-file "/tmp/digest-store")
                         :algorithms #{:md5 :sha-1 :sha-256 :sha-384 :sha-512}
                         :primary :sha-256 })

(def ^:private CONTROL_MAP
  { :algorithms { :get #(set (map (comp keyword trim) (split % #"\s*,+\s*")))
                 :put #(join \, (sort (map name %)))
                 :verify #(subset? % (:algorithms DEFAULTS))
                 :error (str "The only valid algorithms are "
                             (:algorithms DEFAULTS)) }
   :primary { :get keyword :put name
             :verify #(contains? (:algorithms DEFAULTS) %)
             :error (str "Primary algorithm not in " (:algorithms DEFAULTS))
             }
})

;; (defn- -init-conf [args]
;;   "Merge defaults and make sure the base directory is present"
;;   (let [c (if (nil? conf-args) DEFAULTS (merge DEFAULTS conf-args))
;;         d (io/as-file (:dir c))]
;;     ;; make sure the algorithms supplied are supported
;;     (when-not (subset? (:algorithms c) (:algorithms DEFAULTS))
;;       (throw
;;        (IllegalArgumentException. (:error (:algorithms CONTROL_MAP)))))

;;     ;; make sure the primary algorithm is in the supplied algorithm set
;;     (when-not (contains? (:algorithms c) (:primary c))
;;       (throw
;;        (IllegalArgumentException.
;;         "Primary digest algorithm must be in supported algorithms list.")))

;;     ;; this will crap out with the right exception if the directory
;;     ;; stack doesn't exist and/or can't be created
;;     (.mkdirs d)
;;     (assoc c :dir d)))

(defn- init-control [env db conf]
  (merge conf
         (with-db-txn [txn env]
           (into {}
                 ;; iterate over control map
                 (for [k (keys CONTROL_MAP)
                       :let [m (get CONTROL_MAP k)
                             c (get conf k)
                             d (get DEFAULTS k)
                             [_ v] (db-get db (name k) :txn txn)]]
                   (if (nil? v)
                     ;; insert and return conf entry or default
                     (let [vv (or c d)]
                       (db-put db (name k) ((:put m) vv) :txn txn)
                       [k vv])
                     ;; check that database contents match conf input
                     ;; if supplied
                     (let [vv ((:get m) v)]
                       (when-not ((:verify m) vv)
                         (throw (IllegalArgumentException. (:error m))))
                       (if (or (nil? c) (= c vv))
                         [k vv]
                         (throw (IllegalArgumentException.
                                 (str k ": " c " does not match " vv)))))))))))

(defmethod digest-store :fs-bdb [_ & [conf-args]]
  ;;"Create and open a filesystem/Berkeley DB-based digest store."
  ;; initialize config with some stuff
  ;;(println conf-args)
  (let [conf-tmp (update-in (into {} conf-args) [:dir] io/as-file)
        dir (:dir conf-tmp)]
    ;; make sure the parameter is present
    (when (nil? dir)
      (throw (IllegalArgumentException.
              "Filesystem/BerkeleyDB driver needs a :dir parameter")))
    ;; this will throw with the right exception on its own if it fails
    (.mkdirs dir)
    ;; make sure the target subdirs are present
    (doseq [d [TEMP_DIR STORE_DIR]] (.mkdir (io/file dir d)))

    (let [dbconf { :transactional true :allow-create true }
          env (db-env-open dir dbconf)
          control (db-open env "control" dbconf)
          conf (init-control env control conf-tmp)
          entries (into {} (map #(vec [% (db-open env (name %) dbconf)])
                                (:algorithms conf)))]
      ;; handle counts
      (with-db-txn [txn env]
        (doseq [k [:objects :deleted :bytes]
                :let [[_ v] (db-get control (name k) :txn txn)]]
          (when (nil? v)
            (db-put control (name k) "0" :txn txn))))
          
      ;; handle creation/modification times
      (doseq [k [:ctime :mtime] :let [time (get-timestamp control k)]]
        (when (nil? time)
          (store-timestamp control k)))
      ;; return the constructor
      (->FSBDBDigestStore conf env control entries))))
