package com.alness.template.security.filters;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.alness.template.security.configuration.JwtTokenConfig;
import com.alness.template.security.configuration.SimpleGrantedAuthorityJsonCreator;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtValidationFilter extends BasicAuthenticationFilter{
     public JwtValidationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(JwtTokenConfig.PREFIX_TOKEN)) {
            chain.doFilter(request, response);
            return;
        }
        String token = header.replace(JwtTokenConfig.PREFIX_TOKEN, "");

        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(JwtTokenConfig.SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Object authoritiesClaims = claims.get("authorities");

            Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
                    .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityJsonCreator.class)
                    .readValue(authoritiesClaims.toString().getBytes(), SimpleGrantedAuthority[].class));

            UsernamePasswordAuthenticationToken autentication = new UsernamePasswordAuthenticationToken(
                    claims.getSubject(), null, authorities);

            SecurityContextHolder.getContext().setAuthentication(autentication);
            chain.doFilter(request, response);
        } catch (Exception e) {
            Map<String, String> bodyResponse = new HashMap<>();
            bodyResponse.put("error", e.getMessage());
            bodyResponse.put("message", "Invalid jwt token.");
            response.getWriter().write(new ObjectMapper().writeValueAsString(bodyResponse));
            response.setStatus(403);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        }
    }
}
