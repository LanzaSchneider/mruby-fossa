#include <mruby.h>
#include <mruby/data.h>
#include <mruby/class.h>

typedef struct {
	mrb_state* mrb;
	mrb_value proc;
	mrb_value connection;
} mrb_fossa_connection_data;

extern struct mrb_data_type mrb_fossa_manager_type;
extern struct mrb_data_type mrb_fossa_connection_type;

extern struct RClass* fossa_module;
extern struct RClass* fossa_manager_class;
extern struct RClass* fossa_connection_class;
