#include <mruby.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/value.h>
#include <mruby/string.h>
#include <mruby/numeric.h>
#include <mruby/variable.h>

#include <mruby/ext/fossa.h>
#include <fossa.h>

static void mrb_fossa_manager_free_func(mrb_state *mrb, void *ptr) {
	if ( ptr ) {
		ns_mgr_free((struct ns_mgr*)ptr);
		mrb_free(mrb, ptr);
	}
}
struct mrb_data_type mrb_fossa_manager_type = { "Fossa/Manager", mrb_fossa_manager_free_func };

static void mrb_fossa_connection_free_func(mrb_state *mrb, void *ptr) {
	if ( ptr ) {
		struct ns_connection* nc = (struct ns_connection*)ptr;
		nc->flags |= NSF_CLOSE_IMMEDIATELY;
		if ( nc->user_data ) mrb_free(mrb, nc->user_data);
		nc->user_data = NULL;
	}
}
struct mrb_data_type mrb_fossa_connection_type = { "Fossa/Connection", mrb_fossa_connection_free_func };

struct RClass* fossa_module = NULL;
struct RClass* fossa_manager_class = NULL;
struct RClass* fossa_connection_class = NULL;

// =======================================================
// Fossa
// =======================================================
static mrb_value mrb_fossa_version(mrb_state* mrb, mrb_value self) {
	return mrb_str_new_cstr(mrb, NS_FOSSA_VERSION);
}

static mrb_value mrb_fossa_resolve(mrb_state* mrb, mrb_value self) {
	char* domain_name = NULL;
	char buffer[256];
	if ( mrb_get_args(mrb, "z", &domain_name) ) {
		sprintf(buffer, "(failed)");
		ns_resolve(domain_name, buffer, 256);
		return mrb_str_new_cstr(mrb, buffer);
	}
	return mrb_nil_value();
}

static mrb_value mrb_fossa_resolve_all(mrb_state* mrb, mrb_value self) {
	mrb_value result = mrb_ary_new(mrb);
	char* host = NULL;
	struct in_addr ina_;
	struct in_addr* ina = &ina_;
	char host_buffer[256];
	char buffer[256];
	if ( 1 == mrb_get_argc(mrb) && mrb_get_args(mrb, "z", &host) ) {
		
	} else {
		gethostname(host_buffer, 256);
		host = host_buffer;
	}
#ifdef NS_ENABLE_GETADDRINFO
	int rv = 0;
#ifdef _WIN32
	struct addrinfo {
		int ai_flags;
		int ai_family;
		int ai_socktype;
		int ai_protocol;
		size_t ai_addrlen;
		char* ai_canonname;
		struct sockaddr* ai_addr;
		struct addrinfo* ai_next;
	} hints;
#else
	struct addrinfo hints;
#endif

	struct addrinfo *servinfo, *p;
	struct sockaddr_in *h = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((rv = getaddrinfo(host, NULL, NULL, &servinfo)) != 0) {
		DBG(("getaddrinfo(%s) failed: %s", host, strerror(errno)));
		return result;
	}
	for (p = servinfo; p != NULL; p = p->ai_next) {
		memcpy(&h, &p->ai_addr, sizeof(struct sockaddr_in *));
		memcpy(ina, &h->sin_addr, sizeof(*ina));
		sprintf(buffer, "%s", inet_ntoa(ina_));
		mrb_ary_push(mrb, result, mrb_str_new_cstr(mrb, buffer));
	}
	freeaddrinfo(servinfo);
#else
	struct hostent *he;
	if ((he = gethostbyname(host)) == NULL) {
		DBG(("gethostbyname(%s) failed: %s", host, strerror(errno)));
	} else {
		unsigned i = 0;
		for (;; i++) {
			if (!he->h_addr_list[i]) break;
			memcpy(ina, he->h_addr_list[i], sizeof(*ina));
			sprintf(buffer, "%s", inet_ntoa(ina_));
			mrb_ary_push(mrb, result, mrb_str_new_cstr(mrb, buffer));
		}
	}
#endif /* NS_ENABLE_GETADDRINFO */
	return result;
}

static mrb_value mrb_fossa_hostname(mrb_state* mrb, mrb_value self) {
	char host_buffer[256];
	gethostname(host_buffer, 256);
	return mrb_str_new_cstr(mrb, host_buffer);
}

// =======================================================
// Manager
// =======================================================
static mrb_value mrb_fossa_manager_initialize(mrb_state* mrb, mrb_value self) {
	struct ns_mgr* mgr = (struct ns_mgr*)mrb_malloc(mrb, sizeof(struct ns_mgr));
	ns_mgr_init(mgr, NULL);
	DATA_PTR(self) = mgr;
	DATA_TYPE(self) = &mrb_fossa_manager_type;
	return mrb_nil_value();
}

static mrb_value mrb_fossa_manager_poll(mrb_state* mrb, mrb_value self) {
	struct ns_mgr* mgr = (struct ns_mgr*)DATA_PTR(self);
	mrb_int milli;
	if (mgr && mrb_get_args(mrb, "i", &milli)) {
		return mrb_float_value(mrb, ns_mgr_poll(mgr, milli));
	}
	return mrb_nil_value();
}

static mrb_value mrb_fossa_manager_free(mrb_state* mrb, mrb_value self) {
	struct ns_mgr* mgr = (struct ns_mgr*)DATA_PTR(self);
	if (mgr) {
		ns_mgr_free(mgr);
		mrb_free(mrb, mgr);
		DATA_PTR(self) = NULL;
	}
	return mrb_nil_value();
}

static void mrb_fossa_connection_callback(struct ns_connection *nc, int ev, void *p) {
	if ( nc->user_data ) {
		mrb_fossa_connection_data* data = (mrb_fossa_connection_data*)nc->user_data;
		mrb_value argv[] = { data->connection, mrb_fixnum_value(ev), mrb_nil_value() };
		switch ( ev ) {
		// =========================================
		// Common
		// =========================================
		case NS_POLL : break;
		case NS_ACCEPT : {
			union socket_address* addr = (union socket_address*)p;
		} break;
		case NS_CONNECT : {
			int connect_status = *(int*)p;
			if (connect_status) argv[2] = mrb_str_new_cstr(data->mrb, strerror(connect_status));
		} break;
		case NS_RECV : {
			struct mbuf *io = &nc->recv_mbuf;
			argv[2] = mrb_str_new(data->mrb, io->buf, io->len);
			mbuf_remove(io, io->len);
		} break;
		case NS_SEND : break;
		// =========================================
		// HTTP
		// =========================================
		case NS_HTTP_REQUEST :
		case NS_HTTP_REPLY : 
		case NS_HTTP_CHUNK : {
			struct http_message* hm = (struct http_message*)p;
			mrb_value hash = mrb_hash_new(data->mrb);
			#define defr(name) mrb_hash_set(data->mrb, hash, mrb_symbol_value(mrb_intern_lit(data->mrb, #name)), mrb_str_new(data->mrb, hm->name.p, hm->name.len))
			defr(message);
			#undef defr
			argv[2] = hash;
		} break;
		case NS_SSI_CALL : {
			argv[2] = mrb_str_new_cstr(data->mrb, (const char*)p);
		} break;
		
		// =========================================
		// WebSocket
		// =========================================
		case NS_WEBSOCKET_HANDSHAKE_REQUEST : break;
		case NS_WEBSOCKET_HANDSHAKE_DONE : break;
		case NS_WEBSOCKET_FRAME : 
		case NS_WEBSOCKET_CONTROL_FRAME : {
			struct websocket_message* wm = (struct websocket_message*)p;
			mrb_value array = mrb_ary_new(data->mrb);
			mrb_ary_push(data->mrb, array, mrb_str_new(data->mrb, wm->data, wm->size));
			mrb_ary_push(data->mrb, array, mrb_fixnum_value(wm->flags));
			argv[2] = array;
		} break;
		}
		mrb_yield_argv(data->mrb, data->proc, 3, argv);
		// mrb_yield_with_class(data->mrb, data->proc, 3, argv, data->connection, fossa_connection_class);
	}
}

static mrb_value mrb_fossa_manager_bind(mrb_state* mrb, mrb_value self) {
	struct ns_mgr* mgr = (struct ns_mgr*)DATA_PTR(self);
	if (!mgr) return mrb_nil_value();
	
	char* address = NULL;
	mrb_value callback;
	mrb_int flags = 0;
	int argc = mrb_get_argc(mrb);
	
	if (argc == 1 && 1 == mrb_get_args(mrb, "z&", &address, &callback)) {
	} else if (argc == 2 && 2 == mrb_get_args(mrb, "zi&", &address, &flags, &callback)) {}
	
	if ( address && !mrb_nil_p(callback) ) {
		struct ns_bind_opts opts = { NULL, flags, NULL };
		struct ns_connection* nc = ns_bind_opt(mgr, address, mrb_fossa_connection_callback, opts);
		if ( nc ) {
			mrb_fossa_connection_data* data = (mrb_fossa_connection_data*)mrb_malloc(mrb, sizeof(mrb_fossa_connection_data));
			mrb_value connection = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA, fossa_connection_class));
			DATA_PTR(connection) = nc;
			DATA_TYPE(connection) = &mrb_fossa_connection_type;
			mrb_iv_set(mrb, connection, mrb_intern_lit(mrb, "_callback_"), callback);
			data->mrb = mrb;
			data->proc = callback;
			data->connection = connection;
			nc->user_data = data;
			return connection;
		}
	}
	
	return mrb_nil_value();
}

static mrb_value mrb_fossa_manager_connect(mrb_state* mrb, mrb_value self) {
	struct ns_mgr* mgr = (struct ns_mgr*)DATA_PTR(self);
	if (!mgr) return mrb_nil_value();
	
	char* address = NULL;
	mrb_value callback;
	mrb_int flags = 0;
	int argc = mrb_get_argc(mrb);
	
	if (argc == 1 && 1 == mrb_get_args(mrb, "z&", &address, &callback)) {
	} else if (argc == 2 && 2 == mrb_get_args(mrb, "zi&", &address, &flags, &callback)) {}
	
	if ( address && !mrb_nil_p(callback) ) {
		struct ns_connect_opts opts = { NULL, flags, NULL };
		struct ns_connection* nc = ns_connect_opt(mgr, address, mrb_fossa_connection_callback, opts);
		if ( nc ) {
			mrb_fossa_connection_data* data = (mrb_fossa_connection_data*)mrb_malloc(mrb, sizeof(mrb_fossa_connection_data));
			mrb_value connection = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA, fossa_connection_class));
			DATA_PTR(connection) = nc;
			DATA_TYPE(connection) = &mrb_fossa_connection_type;
			mrb_iv_set(mrb, connection, mrb_intern_lit(mrb, "_callback_"), callback);
			data->mrb = mrb;
			data->proc = callback;
			data->connection = connection;
			nc->user_data = data;
			return connection;
		}
	}
	
	return mrb_nil_value();
}

static mrb_value mrb_fossa_manager_connect_http(mrb_state* mrb, mrb_value self) {
	struct ns_mgr* mgr = (struct ns_mgr*)DATA_PTR(self);
	if (!mgr) return mrb_nil_value();
	
	char* url = NULL;
	char* extra_headers = NULL;
	char* post_data = NULL;
	mrb_value callback;
	int argc = mrb_get_argc(mrb);
	
	if (argc == 1 && 1 == mrb_get_args(mrb, "z&", &url, &callback)) {
	} else if (argc == 2 && 2 == mrb_get_args(mrb, "zz&", &url, &extra_headers, &callback)) {
	} else if (argc == 3 && 3 == mrb_get_args(mrb, "zzz&", &url, &extra_headers, &post_data, &callback)) {}
	
	if ( url && !mrb_nil_p(callback) ) {
		struct ns_connection* nc = ns_connect_http(mgr, mrb_fossa_connection_callback, url, extra_headers, post_data);
		if ( nc ) {
			mrb_fossa_connection_data* data = (mrb_fossa_connection_data*)mrb_malloc(mrb, sizeof(mrb_fossa_connection_data));
			mrb_value connection = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA, fossa_connection_class));
			DATA_PTR(connection) = nc;
			DATA_TYPE(connection) = &mrb_fossa_connection_type;
			mrb_iv_set(mrb, connection, mrb_intern_lit(mrb, "_callback_"), callback);
			data->mrb = mrb;
			data->proc = callback;
			data->connection = connection;
			nc->user_data = data;
			return connection;
		}
	}
	
	return mrb_nil_value();
}

// =======================================================
// Connection
// =======================================================
static mrb_value mrb_fossa_connection_initialize(mrb_state* mrb, mrb_value self) {
	mrb_raise(mrb, E_RUNTIME_ERROR, "Can't create Fossa::Connection.\n");
	return mrb_nil_value();
}

static mrb_value mrb_fossa_connection_broadcast(mrb_state* mrb, mrb_value self) {
	struct ns_connection* nc = DATA_PTR(self);
	if (!nc) return mrb_nil_value();
	unsigned flag = 1;
	setsockopt(nc->sock, SOL_SOCKET, SO_BROADCAST, &flag, sizeof(flag));
	return mrb_nil_value();
}

static mrb_value mrb_fossa_connection_close(mrb_state* mrb, mrb_value self) {
	struct ns_connection* nc = DATA_PTR(self);
	if (!nc) return mrb_nil_value();
	nc->flags |= NSF_CLOSE_IMMEDIATELY;
	return mrb_nil_value();
}

static mrb_value mrb_fossa_connection_send(mrb_state* mrb, mrb_value self) {
	struct ns_connection* nc = DATA_PTR(self);
	if (!nc) return mrb_fixnum_value(0);
	mrb_value string;
	if (mrb_get_args(mrb, "S", &string)) {
		return mrb_fixnum_value(ns_send(nc, RSTRING_PTR(string), RSTRING_LEN(string)));
	}
	return mrb_fixnum_value(0);
}

void mrb_lanlv_fossa_gem_init(mrb_state* mrb) {
	fossa_module = mrb_define_module(mrb, "Fossa");
	
	fossa_manager_class = mrb_define_class_under(mrb, fossa_module, "Manager", mrb->object_class);
	
	mrb_define_module_function(mrb, fossa_module, "version", mrb_fossa_version, MRB_ARGS_NONE());
	mrb_define_module_function(mrb, fossa_module, "resolve", mrb_fossa_resolve, MRB_ARGS_REQ(1));
	mrb_define_module_function(mrb, fossa_module, "resolve_all", mrb_fossa_resolve_all, MRB_ARGS_ANY());
	mrb_define_module_function(mrb, fossa_module, "hostname", mrb_fossa_hostname, MRB_ARGS_NONE());
	
	MRB_SET_INSTANCE_TT(fossa_manager_class, MRB_TT_DATA);
	
	mrb_define_method(mrb, fossa_manager_class, "initialize", mrb_fossa_manager_initialize, MRB_ARGS_NONE());
	mrb_define_method(mrb, fossa_manager_class, "poll", mrb_fossa_manager_poll, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, fossa_manager_class, "free", mrb_fossa_manager_free, MRB_ARGS_NONE());
	
	mrb_define_method(mrb, fossa_manager_class, "bind", mrb_fossa_manager_bind, MRB_ARGS_ANY());
	mrb_define_method(mrb, fossa_manager_class, "connect", mrb_fossa_manager_connect, MRB_ARGS_ANY());
	mrb_define_method(mrb, fossa_manager_class, "connect_http", mrb_fossa_manager_connect_http, MRB_ARGS_ANY());
	
	fossa_connection_class = mrb_define_class_under(mrb, fossa_module, "Connection", mrb->object_class);
	
	MRB_SET_INSTANCE_TT(fossa_connection_class, MRB_TT_DATA);
	
	mrb_define_method(mrb, fossa_connection_class, "initialize", mrb_fossa_connection_initialize, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, fossa_connection_class, "broadcast", mrb_fossa_connection_broadcast, MRB_ARGS_NONE());
	mrb_define_method(mrb, fossa_connection_class, "close", mrb_fossa_connection_close, MRB_ARGS_NONE());
	mrb_define_method(mrb, fossa_connection_class, "send", mrb_fossa_connection_send, MRB_ARGS_REQ(1));
	
	#define defc(name) mrb_define_const(mrb, fossa_connection_class, #name, mrb_fixnum_value(name))
	// Common
	defc(NS_POLL);
	defc(NS_ACCEPT);
	defc(NS_CONNECT);
	defc(NS_RECV);
	defc(NS_SEND);
	defc(NS_CLOSE);
	// Http
	defc(NS_HTTP_REQUEST);
	defc(NS_HTTP_REPLY);
	defc(NS_HTTP_CHUNK);
	defc(NS_SSI_CALL);
	// WebSocket
	defc(NS_WEBSOCKET_HANDSHAKE_REQUEST);
	defc(NS_WEBSOCKET_HANDSHAKE_DONE);
	defc(NS_WEBSOCKET_FRAME);
	defc(NS_WEBSOCKET_CONTROL_FRAME);
	#undef defc
}

void mrb_lanlv_fossa_gem_final(mrb_state* mrb) {}























