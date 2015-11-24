(defproject digest-store "0.1.0-SNAPSHOT"
  :description "Unified front end for content-addressable storage using multiple hash algorithms and RFC 6920 URIs"
  :url "https://github.com/doriantaylor/clj-digest-store"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [
                 [org.clojure/clojure "1.7.0"]
                 [digest "1.4.4"]
                 [cupboard "1.0beta1"]
                 [com.novemberain/pantomime "2.7.0"]
                 [byte-streams "0.2.0"]
                 [gloss "0.2.5"] 
                 [commons-codec/commons-codec "1.10"]
                 ])
