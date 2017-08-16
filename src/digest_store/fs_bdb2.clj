(ns digest-store.fs-bdb2
  "Filesystem/Berkeley DB-based driver for digest store (bis)"
  (:use cupboard.bdb.je digest-store.core digest-store.utils
        [clojure.string :only [split trim join]]
        [clojure.set :only [intersection subset?]])
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

(def STORE-DIR "store")
(def TEMP-DIR  "tmp")

(reduce (fn [coll [k v]] (let [off (coll :off)] { :off (+ off v) :out (assoc (coll :out) k [off v]) })) { :off 0 :out {} } (seq ds/digest-sizes))
