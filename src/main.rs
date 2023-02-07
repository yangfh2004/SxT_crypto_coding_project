mod generic;

use anyhow::{anyhow, Context, Result};
use ark_curve25519::Fr;
use ark_ff::biginteger::BigInteger256;
use ark_ff::PrimeField;
use ark_linear_sumcheck::ml_sumcheck::protocol::{ListOfProductsOfPolynomials, PolynomialInfo};
use ark_linear_sumcheck::ml_sumcheck::{MLSumcheck, Proof};
use ark_linear_sumcheck::Error as SumCheckError;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng};
use ark_std::{Zero, One};
use rand;
use generic::{Data, TableOperation};
use std::collections::HashMap;
use std::rc::Rc;
use ark_linear_sumcheck::ml_sumcheck::protocol::verifier::SubClaim;

fn main() {
    println!("SxT Crypto Coding!");
}

impl TableOperation<Fr> for Data<Fr> {
    fn new(exp: usize) -> Self {
        let base: usize = 2;
        let capacity = if exp > 64 { 64} else { base.pow(exp as u32) };
        Self {
            table: HashMap::new(),
            capacity,
            exp,
        }
    }

    fn add_column(&mut self, name: &'static str, data: Option<Vec<Fr>>) {
        if let Some(d) = data {
            if d.len() > self.capacity {
                self.table
                    .insert(name.to_string(), d[..self.capacity].to_vec());
            } else {
                self.table.insert(name.to_string(), d);
            }
        } else {
            self.table
                .insert(name.to_string(), Vec::with_capacity(self.capacity));
        }
    }

    fn product(&self, a: &String, b: &String) -> Result<Vec<Fr>> {
        let a = self
            .table
            .get(a)
            .context("Requested column does not exist!")?;
        let b = self
            .table
            .get(b)
            .context("Requested column does not exist!")?;
        if a.len() != b.len() {
            Err(anyhow!("Column length does not match each other!"))
        } else if a.len() > 0 && b.len() > 0 {
            Ok(a.iter().zip(b.iter()).map(|(a, b)| a * b).collect())
        } else {
            Ok(Vec::new())
        }
    }

    fn get(&self, col: &String) -> Option<&Vec<Fr>> {
        self.table.get(col)
    }

    fn len(&self) -> usize {
        self.table.len()
    }
}

fn gen_random_from_seed(seed: &[u8; 32], exp: usize) -> Vec<Fr> {
    // generate random vector with seed.
    let mut vec_r = Vec::new();
    let mut rng = StdRng::from_seed(seed.to_owned());
    let exp = if exp > 64 { 64 } else { exp };
    let base: usize = 2;
    let limit: usize = base.pow(exp as u32);
    for _ in 0..limit {
        let random = rng.gen_range(0..limit);
        let big_int = BigInteger256::from(random as u64);
        vec_r.push(Fr::from_bigint(big_int).unwrap());
    }
    vec_r
}

struct Victor {
    exp: usize,
}

#[allow(dead_code)]
impl Victor {
    pub fn new(exp: usize) -> Self {
        Self {
            exp: if exp > 64 { 64 } else { exp },
        }
    }

    pub fn verify_proof(&self, proof: &Proof<Fr>, info: &PolynomialInfo) ->  Result<SubClaim<Fr>> {
        MLSumcheck::<Fr>::verify(info, Fr::zero(), proof).context("Cannot verify the proof!")
    }

    pub fn gen_random(&self) -> usize {
        let base: usize = 2;
        let limit: usize = base.pow(self.exp as u32);
        let mut rng = rand::thread_rng();
        rng.gen_range(0..limit)
    }
}

struct Peggy {
    data: Rc<Data<Fr>>,
}

impl Peggy {
    pub fn new(data: Rc<Data<Fr>>) -> Self {
        Self {
            data
        }
    }

    pub fn compute_product(&self, a: &str, b: &str) -> Vec<Fr> {
        let data = self.data.as_ref();
        let a_string = a.to_string();
        let b_string = b.to_string();
        data.product(&a_string, &b_string).unwrap()
    }

    pub fn generate_proof(
        &self,
        seed: &[u8; 32],
        a: &str,
        b: &str,
        prod: Vec<Fr>,
    ) -> Result<(Proof<Fr>, PolynomialInfo), SumCheckError> {
        let data = self.data.as_ref();
        let a_string = a.to_string();
        let b_string = b.to_string();
        let vec_a = data.get(&a_string).unwrap().to_vec();
        let mle_a = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, vec_a);
        let rc_a = Rc::new(mle_a);
        let vec_b = data.get(&b_string).unwrap().to_vec();
        let mle_b = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, vec_b);
        let rc_b = Rc::new(mle_b);
        // generate random vector with seed.
        let vec_r = gen_random_from_seed(seed, data.exp);
        let mle_r = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, vec_r);
        let rc_r = Rc::new(mle_r);
        let mut list = ListOfProductsOfPolynomials::<Fr>::new(data.exp);
        let product = vec![rc_r.clone(), rc_a.clone(), rc_b.clone()];
        list.add_product(product, Fr::one());
        let mle_p = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, prod);
        let rc_p = Rc::new(mle_p);
        let product = vec![rc_r.clone(), rc_p.clone()];
        list.add_product(product, -Fr::one());
        let info = list.info();
        let proof = MLSumcheck::<Fr>::prove(&list)?;
        Ok((proof, info))
    }
}

struct Penelope {
    data: Rc<Data<Fr>>,
}

impl Penelope {
    pub fn new(data: Rc<Data<Fr>>) -> Self {
        Self {
            data
        }
    }

    pub fn generate_eval(&self, col: &str, q: &[Fr]) -> Fr {
        let data = self.data.as_ref();
        let col_string = col.to_string();
        let vec = data.get(&col_string).unwrap().to_vec();
        let mle = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, vec);
        mle.evaluate(q).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;
    use super::*;
    use ark_std::{One, UniformRand, Zero};

    #[test]
    fn test_data_fr() {
        let mut d = Data::<Fr>::new(2);
        let a_data = Some(vec![Fr::one(), Fr::zero(), Fr::one(), Fr::zero()]);
        d.add_column("A", a_data);
        let mut rng = ark_std::test_rng();
        let b_data = Some(vec![
            Fr::zero(),
            Fr::rand(&mut rng),
            Fr::zero(),
            Fr::rand(&mut rng),
        ]);
        d.add_column("B", b_data);
        let col1 = "A".to_string();
        let col2 = "B".to_string();
        let prod = d.product(&col1, &col2).unwrap();
        for p in prod {
            assert_eq!(p, Fr::zero(), "Product does match correct results!");
        }
    }

    #[test]
    fn test_good_proof(){
        let exp = 3;
        let victor = Victor::new(exp);
        // prepare data
        let mut data = Data::new(exp);
        let data_seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let vec_a = gen_random_from_seed(&data_seed, exp);
        let vec_b = gen_random_from_seed(&data_seed, exp);
        data.add_column("A", Some(vec_a));
        data.add_column("B", Some(vec_b));
        let data = Rc::new(data);
        let peggy = Peggy::new(data.clone());
        // step 2: victor request product from peggy.
        let request_product = peggy.compute_product("A", "B");
        // step 3: victor generate a seed and send it to peggy.
        let victor_seed = [
            1, 2, 4, 8, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 123,
        ];
        // step 4 & 5.
        let (proof, info) = peggy.generate_proof(&victor_seed, "A", "B", request_product.clone()).unwrap();
        assert_eq!(MLSumcheck::<Fr>::extract_sum(&proof), Fr::zero(), "Sum is not zero");
        // step 6: victor verify the proof.
        let sub = victor.verify_proof(&proof, &info).unwrap();
        // step 7: victor generate a random index q.
        let q = sub.point;
        // step 8: evaluations
        let penelope = Penelope::new(data.clone());
        let aq = penelope.generate_eval("A", &q);
        let bq = penelope.generate_eval("B", &q);
        // step 9
        let vec_r = gen_random_from_seed(&victor_seed, data.exp);
        let mle_r = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, vec_r);
        let rq = mle_r.evaluate(&q).unwrap();
        let mle_p = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, request_product);
        let pq = mle_p.evaluate(&q).unwrap();
        let fq = rq * (aq * bq - pq);
        assert_eq!(fq, sub.expected_evaluation, "Evaluation does not the expectation.");
    }

    #[test]
    #[should_panic]
    fn test_bad_proof(){
        let exp = 3;
        let victor = Victor::new(exp);
        // prepare data
        let mut data = Data::new(exp);
        let data_seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let vec_a = gen_random_from_seed(&data_seed, exp);
        let vec_b = gen_random_from_seed(&data_seed, exp);
        data.add_column("A", Some(vec_a));
        data.add_column("B", Some(vec_b));
        let data = Rc::new(data);
        let peggy = Peggy::new(data.clone());
        // step 2: victor request product from peggy.
        let request_product = peggy.compute_product("A", "B");
        // step 3: victor generate a seed and send it to peggy.
        let victor_seed = [
            1, 2, 4, 8, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 123,
        ];
        // step 4 & 5.
        let bad_prod: Vec<Fr> = request_product.clone().into_iter().map(|x|x.add(&Fr::one())).collect();
        let (proof, info) = peggy.generate_proof(&victor_seed, "A", "B", bad_prod.clone()).unwrap();
        assert_ne!(MLSumcheck::<Fr>::extract_sum(&proof), Fr::zero(), "Sum should not be zero");
        // step 6: victor verify the proof.
        let sub = victor.verify_proof(&proof, &info).unwrap();
        // step 7: victor generate a random index q.
        let q = sub.point;
        // step 8: evaluations
        let penelope = Penelope::new(data.clone());
        let aq = penelope.generate_eval("A", &q);
        let bq = penelope.generate_eval("B", &q);
        // step 9
        // step 9
        let vec_r = gen_random_from_seed(&victor_seed, data.exp);
        let mle_r = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, vec_r);
        let rq = mle_r.evaluate(&q).unwrap();
        let mle_p = DenseMultilinearExtension::<Fr>::from_evaluations_vec(data.exp, request_product);
        let pq = mle_p.evaluate(&q).unwrap();
        let fq = rq * (aq * bq - pq);
        assert_ne!(fq, sub.expected_evaluation, "Evaluation supposes being not good");

    }
}
