fn main() {
    let mut res = winres::WindowsResource::new();
    res.set("ProductName", "TITAN Vigil");
    res.set("FileDescription", "TITAN Vigil");
    res.set("CompanyName", "TITAN");
    res.set_manifest_file("windows/vigil.manifest");
    res.compile().unwrap();
}
