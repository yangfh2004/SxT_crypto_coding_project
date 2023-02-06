use std::collections::HashMap;
use anyhow::{Result, Context, anyhow};


struct Data {
    table: HashMap<String, Vec<i32>>,
}

impl Data {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    pub fn add_column(&mut self, name: &'static str, data: Option<Vec<i32>>) {
        if let Some(d) = data {
            self.table.insert(name.to_string(), d);
        } else {
            self.table.insert(name.to_string(), Vec::new());
        }
    }

    pub fn product(&self, a: &String, b: &String) -> Result<Vec<i32>>{
        let a = self.table.get(a).context("Requested column does not exist!")?;
        let b = self.table.get(b).context("Requested column does not exist!")?;
        if a.len() != b.len() {
            Err(anyhow!("Column length does not match each other!"))
        } else if a.len() > 0 && b.len() > 0 {
            Ok(a.iter().zip(b.iter()).map(|(a, b)| a*b).collect())
        } else {
            Ok(Vec::new())
        }
    }
}


fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data() {
        let mut d = Data::new();
        d.add_column("A", Some(vec![1, 2, 3, 4]));
        d.add_column("B", Some(vec![5, 6, 7, 8]));
        let col1 = "A".to_string();
        let col2 = "B".to_string();
        let prod = d.product(&col1, &col2).unwrap();
        let res = vec![5, 12, 21, 32];
        for (i, p) in prod.iter().enumerate() {
           assert_eq!(res[i], *p, "Product does match correct results!") ;
        }
    }
}