(ns digest-store.fs-bdb
  "Filesystem/Berkeley DB-based driver for digest store"
  (:use cupboard.bdb.je 
;        [clojure.string :only [split]]
        [digest-store.core :only [DigestStore digest-store]])
  (:require [clojure.java.io :as io])
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
