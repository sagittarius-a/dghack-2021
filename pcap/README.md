## Extracting data

A frame is requesting `/zippassword` http route. In the response body,
there is some base64 encoded data.

Decoding it provides both the password and the zip file.

```
VGpaU0lWSllaRUZ2VkdwTktqTnhDZz09ClBLAwQKAAkIAAAnazFThNkEHzoAAAAuAAAABgAcAOaX
l+W5n1VUCQADGntEYRp7RGF1eAsAAQToAwAABOkDAADNTNMdVs2aAiv/QpGicu9gTusiwYydh7P8
PAIintAsmf9naL7Zl3FVktVleWKCUUQnG9TVKXa3aZl/UEsHCITZBB86AAAALgAAAFBLAQIeAwoA
CQgAACdrMVOE2QQfOgAAAC4AAAAGABgAAAAAAAEAAACkgQAAAADml5fluZ9VVAUAAxp7RGF1eAsA
AQToAwAABOkDAABQSwUGAAAAAAEAAQBMAAAAigAAAAAA
```

## Zip password

`N6R!RXdAoTjM*3q`

## Flag

`DGA{582158848efebaee4d501e98768b012f104cf03c}`
