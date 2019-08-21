MRuby::Gem::Specification.new('lanlv-fossa') do |spec|
	spec.license = 'Public domain'
	spec.authors = 'Lanza Schneider'
	
	if ( /mswin|mingw|win32/ =~ RUBY_PLATFORM ) then
		spec.linker.libraries << "wsock32"
		# spec.linker.libraries << "ws2_32"
	end
end
