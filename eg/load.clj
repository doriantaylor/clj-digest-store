(require '[digest-store.core :as ds])
(require 'digest-store.fs-bdb)
(require '[digest-store.utils :as du])
(require '[clojure.java.io :as io])

(time (def my-ds (ds/digest-store :fs-bdb { :dir "/tmp/digest-store" })))

(time
 (def my-objs
   (doall
    (for [x (filter #(and (.isFile %) (<= (.length %) 10485760))
                    (file-seq (io/as-file "/Users/dorian/Downloads")))]
      (ds/store-add my-ds x)))))
