mod_download_token.la: mod_download_token.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_download_token.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_download_token.la
