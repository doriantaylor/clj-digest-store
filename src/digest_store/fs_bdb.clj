(ns digest-store.fs-bdb
  "Filesystem/Berkeley DB-based driver for digest store"
  (:use cupboard.bdb.je
        [clojure.string :only [split trim]]
        [digest-store.core :only [DigestStore digest-store]])
  (:require digest [clojure.java.io :as io] [gloss.core :as g])
  (:import [java.util Date Arrays] [java.io InputStream OutputStream])
)

(defn- tee-streams
  "Return a byte array from an input stream while writing it to an
  output stream."
  [^InputStream in ^OutputStream out]
  (let [^bytes buffer (byte-array digest/*buffer-size*)
        size (.read in buffer)]
    (when (> size 0)
      (.write out buffer)
      (= size digest/*buffer-size* buffer (Arrays/copyOf buffer size)))))

(defn- tee-seq
  "Produce a lazy sequence of byte arrays, suitable for message digest
  processing, while at the same time writing to an output stream."
  [^InputStream in ^OutputStream out]
  (take-while (complement nil?) (repeatedly #(tee-streams in out))))

(defmulti ^:private fs-bdb-store-add 
  (fn [store item] (type item)))

;(defmethod fs-bdb-store-add Sto

(defrecord FSBDBDigestStore [conf env control entries]
  DigestStore
  (store-add [store item] (fs-bdb-store-add store item))
  (store-close [store]
    (doseq [db (cons control (map #(get entries %) (keys entries)))]
      ;;(if (not (nil? (:val db))) (db-close db))
      (db-close db)
      ;;(println db) 
      )
    (db-env-checkpoint env)
    (db-env-clean-log env)
    (db-env-close env))
    ;; (if (not (nil? (:val env))) (db-env-close env)))
  ;; (store-get [store rec])
  ;; (store-remove [store rec])
  ;; (store-forget [store rec])
  ;; (store-stats [store])
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

