pub fn median(values: &Vec<u64>) -> u64 {
    let size = values.len();
    let mut data: Vec<u64> = Vec::new();
    for v in values.iter() {
        if !data.contains(v) {
            data.push(*v);
        }
    }
    let mid_pt = (data.len() / 2) + 1;
    data.sort_by(|a, b| a.cmp(b));
    if size % 2 == 0 {
        let first = data[mid_pt - 1];
        let second = data[mid_pt - 2];
        second + ((first - second) / 2)
    } else {
        data[mid_pt]
    }
}
