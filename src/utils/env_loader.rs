use std::{
    collections::HashMap,
    env::current_dir,
    fs::File,
    io::{BufRead, BufReader, Result},
};

fn parse_line(line: String) -> Option<(String, String)> {
    let split: Vec<&str> = line.split("=").collect();

    if split.len() < 2 {
        return None;
    };

    let var_name = split[0];
    let var_val = split[1..].join("=");

    return Some((var_name.to_string(), var_val));
}

pub fn load_env() -> Result<HashMap<String, String>> {
    let env_path = current_dir()?.join(".env");

    let mut env_hashmap = HashMap::new();

    if !env_path.exists() || !env_path.is_file() {
        return Ok(env_hashmap);
    };

    let file = File::open(env_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        match line {
            Ok(val) => {
                if let Some((name, value)) = parse_line(val) {
                    env_hashmap.insert(name, value);
                };
            }
            Err(_) => continue,
        }
    }

    Ok(env_hashmap)
}
