package com.alness.template.security.filters;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.alness.template.enums.AllowedProfiles;
import com.alness.template.security.configuration.JwtTokenConfig;
import com.alness.template.security.dto.AuthenticationDto;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        AuthenticationDto user = new AuthenticationDto();
        try {
            user = new ObjectMapper().readValue(request.getInputStream(), AuthenticationDto.class);
            log.info("user request logint: {}", user);
        } catch (StreamReadException e) {
            log.error("Error stream read: {}", e.getMessage());
            e.printStackTrace();
        } catch (DatabindException e) {
            log.error("Error databind: {}", e.getMessage());
            e.printStackTrace();
        } catch (IOException e) {
            log.error("Error io: {}", e.getMessage());
            e.printStackTrace();
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        String username = ((User) authResult.getPrincipal()).getUsername();

        Collection<? extends GrantedAuthority> profiles = authResult.getAuthorities();
        boolean isAdmin = profiles.stream().anyMatch(res -> res.getAuthority().equals(AllowedProfiles.ADMIN.getName()));
        
        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(profiles));
        claims.put("isAdmin", isAdmin);
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .signWith(JwtTokenConfig.SECRET_KEY)
                .setIssuedAt(new Date())
                .setExpiration(new Date(this.getTimeToken(24L))) // expiracion en 24 horas
                .compact();

        response.addHeader(HttpHeaders.AUTHORIZATION, JwtTokenConfig.PREFIX_TOKEN + token);
        Map<String, Object> bodyResponse = new HashMap<>();
        bodyResponse.put("access_token", token);
        bodyResponse.put("message", "I log in with a valid user.");
        response.getWriter().write(new ObjectMapper().writeValueAsString(bodyResponse));
        response.setStatus(202);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        Map<String, Object> bodyResponse = new HashMap<>();
        bodyResponse.put("message", "User authentication error or incorrect password.");
        bodyResponse.put("error", failed.getMessage());
        response.getWriter().write(new ObjectMapper().writeValueAsString(bodyResponse));
        response.setStatus(401);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }


    private Long getTimeToken(Long hour){
        return System.currentTimeMillis() + (hour * 60 * 60 * 1000);
    }
}
