pub fn overflow() {
    let mut x: u8 = 255;
    x += 1; // overflow
    println!("{}", x);
}
