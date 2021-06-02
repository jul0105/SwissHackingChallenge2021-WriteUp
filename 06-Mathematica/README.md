# Mathematica

> Author : jul0105
> Date : 13.03.2021



## Challenge info

**Release** : Bundle 2 (13.03)

**Difficulty** : Easy

**Goal** : Solve this math problem to get the flag.



## Solve

1. We need a SMT solver to be able to get the flag. I used this online solver  : https://cvc4.github.io/app
2. Then, rewrite equations in SMT-LIB2 format :

```
(set-logic ALL)
(set-option :produce-models true)
(declare-fun a () Int)
(declare-fun b () Int)
(declare-fun c () Int)
(declare-fun d () Int)

(assert (> a 400000))
(assert (= (mod a 30) 5))
40000001781
(assert (> b 30000000000000000))
(assert (< (* a a) b))
(assert (= (mod b 2400000000000000) 3))

(assert (= (* 2 (+ a b)) (+ c (* d 100))))

(assert (> d 40000000000))
(assert (= (mod (* d 25) 4) 1))
(assert (= (mod d 99) 3))
(assert (= (mod d 5) 1))

(check-sat)
(get-model)
```
3. The solver give me the value of variables :
   1. a = 400025, 
   2. b = 31200000000000003, 
   3. c = 62396000000621956, 
   4. d = 40000001781
4. Flag :

```
shc2021{n1c3_sMt_s0lv3r_m0v3z}
```
