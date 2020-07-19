package com.danielqueiroz.fooddelivery.auth.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.danielqueiroz.fooddelivery.auth.domain.Usuario;
import com.danielqueiroz.fooddelivery.auth.domain.UsuarioRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {

	@Autowired
	private UsuarioRepository usuarioRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Usuario usuario = usuarioRepository.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com email informado"));
		
		return new AuthUser(usuario);
	}

}
