fn main() {
    let mut res = winres::WindowsResource::new();
    res.set("ProductName", "TITAN Operative Community Edition");
    res.set("FileDescription", "TITAN Operative Community Edition");
    res.set("CompanyName", "TITAN");
    res.compile().unwrap();
}