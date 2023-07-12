package com.example.kakao.user;

import com.example.kakao._core.errors.GlobalExceptionHandler;
import com.example.kakao._core.errors.exception.Exception400;
import com.example.kakao._core.errors.exception.Exception401;
import com.example.kakao._core.errors.exception.Exception404;
import com.example.kakao._core.errors.exception.Exception500;
import com.example.kakao._core.security.CustomUserDetails;
import com.example.kakao._core.security.JWTProvider;
import com.example.kakao._core.utils.ApiUtils;
import com.example.kakao.log.ErrorLog;
import com.example.kakao.log.ErrorLogJPARepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.Errors;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@RestController
public class UserRestController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final GlobalExceptionHandler globalExceptionHandler;

    @PostMapping("/join")
    public ResponseEntity<?> join(@RequestBody @Valid UserRequest.JoinDTO requestDTO, Errors errors,
                                  HttpServletRequest request) {

        if (errors.hasErrors()) {
            List<FieldError> fieldErrors = errors.getFieldErrors();
            Exception400 ex = new Exception400(fieldErrors.get(0).getDefaultMessage() + ":" + fieldErrors.get(0).getField());
            return new ResponseEntity<>(
                    ex.body(),
                    ex.status()
            );
        }
        try {
            userService.join(requestDTO);
            return ResponseEntity.ok().body(ApiUtils.success(null));
        }catch (RuntimeException e){
            return globalExceptionHandler.handle(e, request);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid UserRequest.LoginDTO loginDTO, Errors errors) {

        if (errors.hasErrors()) {
            List<FieldError> fieldErrors = errors.getFieldErrors();
            Exception400 ex = new Exception400(fieldErrors.get(0).getDefaultMessage() + ":" + fieldErrors.get(0).getField());
            return new ResponseEntity<>(
                    ex.body(),
                    ex.status()
            );
        }

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword());
        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        CustomUserDetails myUserDetails = (CustomUserDetails) authentication.getPrincipal();
        String jwt = JWTProvider.create(myUserDetails.getUser());

        return ResponseEntity.ok().header(JWTProvider.HEADER, jwt).body(ApiUtils.success(null));
    }

    // 이메일 중복체크 (기능에는 없지만 사용중)
    @PostMapping("/check")
    public ResponseEntity<?> check(@RequestBody UserRequest.EmailCheckDTO emailCheckDTO) {
        return ResponseEntity.ok().body(ApiUtils.success(null));
    }

    // (기능3) - 로그아웃
    // 사용 안함 - 프론트에서 localStorage JWT 토큰을 삭제하면 됨.
    @GetMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> user) {
        return ResponseEntity.ok().header(JWTProvider.HEADER, "").body(ApiUtils.success(null));
    }
}
