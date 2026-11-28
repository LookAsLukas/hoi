(ns main
  (:require [clojure.test :refer [deftest is run-tests]]))

(defn parallel-filter
  [pred block-size window-size coll]
  (let [blocks (partition-all block-size coll)]
    (letfn [(fill-window [remaining pending]
              (if (or (>= (count pending) window-size) (empty? remaining))
                [remaining pending]
                (recur (rest remaining)
                       (conj pending
                             (future (filterv pred (first remaining)))))))
            (emit [remaining pending]
              (lazy-seq
                (let [[remaining pending] (fill-window remaining pending)]
                  (when (seq pending)
                    (concat (deref (first pending))
                            (emit remaining (subvec pending 1)))))))]
      (emit blocks []))))

(defn elapsed-ms
  [f]
  (let [start (System/nanoTime)]
    (f)
    (quot (- (System/nanoTime) start) 1000000)))

(defn prime?
  [number]
  (and (>= number 2)
       (or (= number 2)
           (and (odd? number)
                (not-any? (fn [divisor] (zero? (mod number divisor)))
                          (range 3 (inc (long (Math/sqrt number))) 2))))))

(deftest input-matches-filter
  (let [numbers (vec (range 50))]
    (is (= (filter odd? numbers)
           (parallel-filter odd? 8 3 numbers)))))

(deftest empty-input-produces-empty-output
  (is (empty? (parallel-filter odd? 8 3 []))))

(defn run-demo
  []
  (let [numbers (vec (range 1000000 2000000))
        sequential-ms (elapsed-ms (fn []
                                    (count (filter prime? numbers))))
        parallel-ms (elapsed-ms (fn []
                                  (count (parallel-filter prime? 500 4 numbers))))]
    (println "Sequential filter:" sequential-ms "ms")
    (println "Parallel filter (block 500, window 4):" parallel-ms "ms")))
