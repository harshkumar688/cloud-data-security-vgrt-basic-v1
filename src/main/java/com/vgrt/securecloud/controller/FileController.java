package com.vgrt.securecloud.controller;

import com.vgrt.securecloud.service.FileService;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class FileController {
    private final FileService files;
    public FileController(FileService files) { this.files = files; }

    @PostMapping("/files")
    public String upload(@RequestParam("file") MultipartFile file,
                         @RequestParam(value = "redirect", required = false) String redirect,
                         Authentication auth,
                         RedirectAttributes flash) {
        try {
            var saved = files.upload(auth.getName(), file.getOriginalFilename(), file.getContentType(), file.getBytes());
            flash.addFlashAttribute("success", "File '" + saved.getOriginalName() + "' sealed with AES-256-GCM and stored.");
            flash.addFlashAttribute("lastUploadedId", saved.getId());
        } catch (IllegalArgumentException ex) {
            flash.addFlashAttribute("error", ex.getMessage());
        } catch (Exception ex) {
            flash.addFlashAttribute("error", "Upload failed: " + ex.getMessage());
        }

        if (redirect != null && redirect.startsWith("/")) {
            return "redirect:" + redirect;
        }
        return "redirect:/files";
    }

    @PostMapping("/files/{id}/download")
    public ResponseEntity<byte[]> download(@PathVariable Long id, Authentication auth) throws Exception {
        var file = files.download(auth.getName(), id);
        var disposition = ContentDisposition.attachment().filename(file.filename(), StandardCharsets.UTF_8).build();
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .contentType(MediaType.APPLICATION_OCTET_STREAM).body(file.content());
    }

    @PostMapping("/files/{id}/verify")
    public String verify(@PathVariable Long id,
                         @RequestParam(value = "redirect", required = false) String redirect,
                         Authentication auth,
                         RedirectAttributes flash) {
        boolean valid = files.verifyIntegrity(auth.getName(), id);
        if (valid) {
            flash.addFlashAttribute("success", "Integrity Verified: SHA-256 hash matched and ciphertext authentication tag valid.");
        } else {
            flash.addFlashAttribute("error", "Integrity Warning: Cryptographic check failed or object payload modified.");
        }

        if (redirect != null && redirect.startsWith("/")) {
            return "redirect:" + redirect;
        }
        return "redirect:/files";
    }

    @PostMapping("/files/{id}/delete")
    public String delete(@PathVariable Long id,
                         @RequestParam(value = "redirect", required = false) String redirect,
                         Authentication auth,
                         RedirectAttributes flash) {
        try {
            files.delete(auth.getName(), id);
            flash.addFlashAttribute("success", "File permanently purged from encrypted enclave storage.");
        } catch (Exception ex) {
            flash.addFlashAttribute("error", "Deletion failed: " + ex.getMessage());
        }

        if (redirect != null && redirect.startsWith("/")) {
            return "redirect:" + redirect;
        }
        return "redirect:/files";
    }

    @PostMapping(value = "/api/files/{id}/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> apiVerify(@PathVariable Long id, Authentication auth) {
        boolean valid = files.verifyIntegrity(auth.getName(), id);
        return ResponseEntity.ok(Map.of(
            "fileId", id,
            "status", valid ? "VERIFIED" : "COMPROMISED",
            "algorithm", "SHA-256 + AES-GCM Tag",
            "timestamp", java.time.Instant.now().toString()
        ));
    }
}
