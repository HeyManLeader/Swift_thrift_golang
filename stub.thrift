namespace go stub

struct Image {
  1: string path,
  2: i32 size,
  3: binary content,
}

service UploadServer {
  string upload(1:Image img),
}
