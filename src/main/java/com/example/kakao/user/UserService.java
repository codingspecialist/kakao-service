package com.example.kakao.user;

import com.example.kakao._core.errors.exception.Exception400;
import com.example.kakao._core.errors.exception.Exception401;
import com.example.kakao._core.errors.exception.Exception500;
import com.example.kakao._core.security.CustomUserDetails;
import com.example.kakao._core.security.JWTProvider;
import com.example.kakao.log.ErrorLogJPARepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Transactional(readOnly = true)
@RequiredArgsConstructor
@Service
public class UserService {
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserJPARepository userJPARepository;
    private final ErrorLogJPARepository errorLogJPARepository;

    public UserResponse.FindById findById(Integer id){
        User userPS = userJPARepository.findById(id).orElseThrow(
                () -> new Exception400("회원 아이디를 찾을 수 없습니다. : "+id)
        );
        return new UserResponse.FindById(userPS);
    }

    @Transactional
    public void join(UserRequest.JoinDTO requestDTO) {
        sameCheckEmail(requestDTO.getEmail());

        requestDTO.setPassword(passwordEncoder.encode(requestDTO.getPassword()));
        try {
            userJPARepository.save(requestDTO.toEntity());
        } catch (Exception e) {
            throw new Exception500("unknown server error");
        }
    }

    public String login(UserRequest.LoginDTO requestDTO) {
        try {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                    = new UsernamePasswordAuthenticationToken(requestDTO.getEmail(), requestDTO.getPassword());
            Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
            CustomUserDetails myUserDetails = (CustomUserDetails) authentication.getPrincipal();
            return JWTProvider.create(myUserDetails.getUser());
        } catch (Exception e) {
            throw new Exception401("인증되지 않았습니다");
        }
    }

    public void sameCheckEmail(String email) {
        Optional<User> userOP = userJPARepository.findByEmail(email);
        if (userOP.isPresent()) {
            throw new Exception400("동일한 이메일이 존재합니다 : " + email);
        }
    }


    @Transactional
    public void updatePassword(UserRequest.UpdatePasswordDTO requestDTO, Integer id) {
        User userPS = userJPARepository.findById(id).orElseThrow(
                () -> new Exception400("회원 아이디를 찾을 수 없습니다. : "+id)
        );

        // 의미 있는 setter 추가
        String encPassword =
                passwordEncoder.encode(requestDTO.getPassword());
        userPS.updatePassword(encPassword);
    } // 더티체킹 flush
}
