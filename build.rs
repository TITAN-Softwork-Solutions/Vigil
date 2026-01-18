fn main() {
    let mut res = winres::WindowsResource::new();
    res.set("ProductName", "TITAN Operative");
    res.set("FileDescription", "TITAN Operative");
    res.set("CompanyName", "TITAN");
    res.compile().unwrap();
}