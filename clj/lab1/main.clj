(defn strings-no-repeat
  [alphabet n]
  (if (zero? n)
    (list "")
    (mapcat (fn [s]
              (map (fn [c] (str s c))
                   (remove (fn [c]
                             (and (seq s)
                                  (= c (subs s (dec (count s))))))
                           alphabet)))
            (strings-no-repeat alphabet (dec n)))))
