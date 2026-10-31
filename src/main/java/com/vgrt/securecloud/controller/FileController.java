package com.vgrt.securecloud.controller;

import com.vgrt.securecloud.service.FileService;
import java.nio.charset.StandardCharsets;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class FileController {
    private final FileService files;
    public FileController(FileService files) { this.files = files; }

    @PostMapping("/files")
    public String upload(@RequestParam("file") MultipartFile file, Authentication auth, RedirectAttributes flash) {
        try {
            files.upload(auth.getName(), file.getOriginalFilename(), file.getContentType(), file.getBytes());
            flash.addFlashAttribute("success", "File encrypted and stored.");
        } catch (IllegalArgumentException ex) { flash.addFlashAttribute("error", ex.getMessage()); }
        catch (Exception ex) { flash.addFlashAttribute("error", "Upload failed. Check server configuration and try again."); }
        return "redirect:/";
    }

    @PostMapping("/files/{id}/download")
    public ResponseEntity<byte[]> download(@PathVariable Long id, Authentication auth) throws Exception {
        var file = files.download(auth.getName(), id);
        var disposition = ContentDisposition.attachment().filename(file.filename(), StandardCharsets.UTF_8).build();
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .contentType(MediaType.APPLICATION_OCTET_STREAM).body(file.content());
    }
}
