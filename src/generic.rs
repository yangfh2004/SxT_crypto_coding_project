use std::collections::HashMap;
use anyhow::Result;

pub struct Data<T> {
    pub(crate) table: HashMap<String, Vec<T>>,
    pub(crate) capacity: usize,
    pub exp: usize,
}

pub trait TableOperation<T> {
    fn new(exp: usize) -> Self;
    fn add_column(&mut self, name: &'static str, data: Option<Vec<T>>);
    fn product(&self, a: &String, b: &String) -> Result<Vec<T>>;
    fn get(&self, col: &String) -> Option<&Vec<T>>;
    fn len(&self) -> usize;
}
