(ns main
  (:require [clojure.test :refer [deftest is run-tests]]))

(defn sieve
  [numbers]
  (lazy-seq
    (let [prime (first numbers)]
      (cons prime
            (sieve (remove (fn [number] (zero? (mod number prime)))
                           (rest numbers)))))))

(def primes
  (sieve (iterate inc' 2)))

(defn prime?
  [number]
  (and (>= number 2)
       (or (= number 2)
           (and (odd? number)
                (not-any? (fn [divisor] (zero? (mod number divisor)))
                          (range 3 (inc (long (Math/sqrt number))) 2))))))

(deftest starts-with-the-known-primes
  (is (= (list 2 3 5 7 11 13 17 19 23 29)
         (take 10 primes))))

(deftest every-produced-number-is-prime
  (is (every? prime? (take 100 primes))))

(deftest thousandth-prime-is-7919
  (is (= 7919 (nth primes 999))))
