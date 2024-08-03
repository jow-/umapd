#define _GNU_SOURCE

#include <getopt.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "ucode/module.h"
#include "ucode/platform.h"

typedef struct {
	char *name;
	char type, store, action;
	bool is_short;
	int has_arg, val;
	uc_value_t *defval;
} option_spec_t;


static void *
getopt_report_error(uc_vm_t *vm, uc_value_t *errcb, const char *fmt, ...)
{
	char *msg = NULL;
	int len = 0;
	va_list ap;

	va_start(ap, fmt);
	len = xvasprintf(&msg, fmt, ap);
	va_end(ap);

	if (errcb) {
		uc_vm_stack_push(vm, ucv_get(errcb));
		uc_vm_stack_push(vm, ucv_string_new_length(msg, len));

		if (uc_vm_call(vm, false, 1) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(vm));
	}
	else {
		fprintf(stderr, "%s\n", msg);
	}

	free(msg);

	return NULL;
}

static size_t
getopt_parse_defs(uc_value_t *defs, option_spec_t **specsp,
                  char **optstrp, struct option **longoptsp)
{
	struct { size_t count; struct option *entries; } longopts = { 0 };
	struct { size_t count; option_spec_t *entries; } specs = { 0 };
	struct { size_t count; char *entries; } optstr = { 0 };

	for (size_t i = 0; i < ucv_array_length(defs); i++) {
		uc_value_t *def = ucv_array_get(defs, i);
		size_t len = ucv_string_length(def);
		char *str = ucv_string_get(def);

		if (str == NULL || len == 0)
			continue;

		option_spec_t spec = { 0 };
		char *type;

		/* option with required arg */
		if ((type = strchr(str, '=')) != NULL) {
			if (type[1] != 'f' && type[1] != 'i' && type[1] != 's')
				continue; /* invalid type */

			if (type[2] != '\0' && type[2] != '#' && type[2] != '*')
				continue; /* invalid storage type */

			spec.has_arg = 1;
			spec.type = type[1];
			spec.store = type[2];

			len = type - str;
		}

		/* option with optional arg */
		else if ((type = strchr(str, ':')) != NULL) {
			char *p = type + 1;

			switch (*p) {
			case 'f': case 'i': case 's':
				spec.type = *p++;
				break;

			case '-': case '.':
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				char *e;
				long ival = strtol(p, &e, 10);

				if (e == p)
					continue; /* invalid number */

				if (*e == '.') {
					spec.type = 'f';
					spec.defval = ucv_double_new(strtod(p, &e));
				}
				else {
					spec.type = 'i';
					spec.defval = ucv_int64_new(ival);
				}

				p = e;
				break;

			case '+':
				spec.type = 'i';
				spec.action = '+';
				break;

			default:
				continue; /* invalid type */
			}

			if (*p != '\0' && *p != '#' && *p != '*')
				continue; /* invalid target type */

			spec.has_arg = 2;
			spec.store = *p;

			len = type - str;
		}

		/* negatable flag option */
		else if (str[len - 1] == '!') {
			spec.action = '!';
			len--;
		}

		/* counted flag option */
		else if (str[len - 1] == '+') {
			spec.action = '+';
			len--;
		}

		/* skip definitions with empty name */
		if (len == 0)
			continue;

		/* assume one-letter names to be short options, to force long,
		   a spec might append an empty alias, e.g. `x|` */
		if (len == 1) {
			xasprintf(&spec.name, "%c", *str);
			spec.is_short = true;
			spec.val = *str;

			uc_vector_push(&optstr, spec.val);

			if (spec.has_arg > 0) uc_vector_push(&optstr, ':');
			if (spec.has_arg > 1) uc_vector_push(&optstr, ':');
		}
		else {
			xasprintf(&spec.name, "%.*s", (int)len, str);
			spec.val = 256 + i;

			for (char *p = spec.name, *q = p; p <= spec.name + len; p++) {
				if (*p == '|' || *p == '\0') {
					if (p > q) {
						uc_vector_push(&longopts, ((struct option){
							.name = q,
							.has_arg = spec.has_arg,
							.flag = NULL,
							.val = spec.val
						}));
					}

					*p = '\0';
					q = p + 1;
				}
			}
		}

		uc_vector_push(&specs, spec);
	}

	uc_vector_push(&optstr, 0);
	uc_vector_push(&longopts, ((struct option){ 0 }));

	*specsp = specs.entries;
	*optstrp = optstr.entries;
	*longoptsp = longopts.entries;

	return specs.count;
}

static uc_value_t *
getopt_parse_opt(uc_vm_t *vm, option_spec_t *spec, const char *optarg,
                 uc_value_t *errcb)
{
	if (spec->has_arg == 0) {
		if (optarg)
			return getopt_report_error(vm, errcb,
				"Option '%s' must not have a value", spec->name);

		return ucv_boolean_new(false);
	}
	else if (spec->has_arg == 1) {
		if (!optarg)
			return getopt_report_error(vm, errcb,
				"Option '%s' requires a value", spec->name);
	}

	if (spec->type == 'i') {
		if (optarg) {
			char *e;
			long val = strtol(optarg, &e, 10);

			if (e == optarg || *e != '\0')
				return getopt_report_error(vm, errcb,
					"Option '%s' requires an integer, got '%s'",
					spec->name, optarg);

			return ucv_int64_new(val);
		}
		else if (spec->defval) {
			return ucv_get(spec->defval);
		}
		else {
			return ucv_int64_new(0);
		}
	}
	else if (spec->type == 'f') {
		if (optarg) {
			char *e;
			double val = strtod(optarg, &e);

			if (e == optarg || *e != '\0')
				return getopt_report_error(vm, errcb,
					"Option '%s' requires a fractional value, got '%s'",
					spec->name, optarg);

			return ucv_double_new(val);
		}
		else if (spec->defval) {
			return ucv_get(spec->defval);
		}
		else {
			return ucv_double_new(0.0);
		}
	}

	return ucv_string_new(optarg ? optarg : "");
}

static void
getopt_append(uc_vm_t *vm, uc_value_t *result,
              option_spec_t *spec, const char *optname, uc_value_t *value)
{
	uc_value_t *existing = ucv_object_get(result, spec->name, NULL);
	uc_value_t *uvfalse = ucv_boolean_new(false);

	if (spec->store == '#') {
		if (!existing) {
			existing = ucv_object_new(vm);
			ucv_object_add(result, spec->name, existing);
		}

		if (ucv_type(value) == UC_STRING) {
			char *v = ucv_string_get(value);
			char *eq = strchr(v, '=');

			if (eq) {
				char *k; xasprintf(&k, "%.*s", (int)(eq - v), v);
				ucv_object_add(existing, k, ucv_string_new(eq + 1));
				free(k);
			}
			else {
				ucv_object_add(existing, v, ucv_boolean_new(true));
			}
		}
		else {
			if (value == uvfalse) {
				if (spec->action == '+') {
					uc_value_t *existing_val = ucv_object_get(existing,
						optname ? optname : spec->name, NULL);

					value = ucv_int64_new(ucv_int64_get(existing_val) + 1);
				}
				else {
					value = ucv_boolean_new(true);
				}
			}
			else {
				value = ucv_get(value);
			}

			ucv_object_add(existing, optname ? optname : spec->name, value);
		}
	}
	else if (spec->store == '*') {
		if (!existing) {
			existing = ucv_array_new(vm);
			ucv_object_add(result, spec->name, existing);
		}

		if (value == uvfalse) {
			if (spec->action == '+') {
				size_t existing_len = ucv_array_length(existing);

				if (existing_len > 0) {
					uc_value_t *existing_val =
						ucv_array_get(existing, existing_len - 1);

					value = ucv_int64_new(ucv_int64_get(existing_val) + 1);

					ucv_array_pop(existing);
				}
				else {
					value = ucv_int64_new(1);
				}
			}
			else {
				value = ucv_string_new(optname ? optname : spec->name);
			}
		}
		else {
			value = ucv_get(value);
		}

		ucv_array_push(existing, value);
	}
	else {
		if (value == uvfalse) {
			if (spec->action == '+')
				value = ucv_int64_new(ucv_int64_get(existing) + 1);
			else
				value = ucv_boolean_new(true);
		}
		else {
			value = ucv_get(value);
		}

		ucv_object_add(result, spec->name, value);
	}

	ucv_put(value);
}

static uc_value_t *
uc_getopt(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *defs, *args, *errcb, *result;
	size_t num_specs, argc, extra;
	struct option *longopts;
	option_spec_t *specs;
	char **argv, *optstr;
	int c, longidx = -1;

	defs = uc_fn_arg(0);
	args = uc_fn_arg(1);
	errcb = uc_fn_arg(2);

	if ((defs != NULL && ucv_type(defs) != UC_ARRAY) ||
	    (args != NULL && ucv_type(args) != UC_ARRAY) ||
	    (errcb != NULL && !ucv_is_callable(errcb)))
		return NULL;

	num_specs = getopt_parse_defs(defs, &specs, &optstr, &longopts);

	if (args == NULL)
		args = ucv_object_get(uc_vm_scope_get(vm), "ARGV", NULL);

	argc = ucv_array_length(args);
	extra = 0;

	for (size_t i = 0; i < argc; i++)
		extra += (ucv_type(ucv_array_get(args, i)) != UC_STRING);

	argv = xcalloc(argc + 1 + extra, sizeof(char *));

	for (size_t i = 0; i < argc; i++) {
		uc_value_t *arg = ucv_array_get(args, i);

		if (ucv_type(arg) == UC_STRING)
			argv[i + 1] = _ucv_string_get(((uc_array_t *)args)->entries + i);
		else
			argv[i + 1] = argv[argc + 1 + i] = ucv_to_string(vm, arg);
	}

	result = ucv_object_new(vm);
	optind = 1;
	opterr = 0;

	while ((c = getopt_long(argc + 1, argv, optstr, longopts, &longidx)) != -1) {
		struct option *longopt = NULL;
		option_spec_t *spec = NULL;

		if (c == '?')
			c = optopt;

		if (c >= 256)
			longopt = &longopts[longidx];

		for (size_t i = 0; i < num_specs; i++) {
			if (specs[i].val == c) {
				spec = &specs[i];
				break;
			}
		}

		if (spec) {
			uc_value_t *argval = getopt_parse_opt(vm, spec, optarg, errcb);

			if (argval)
				getopt_append(vm, result, spec,
					longopt ? longopt->name : NULL, argval);
		}
	}

	for (size_t i = 0; i < extra; i++)
		free(argv[argc + 1 + i]);

	for (size_t i = 0; i < num_specs; i++)
		free(specs[i].name);

	free(longopts);
	free(optstr);
	free(specs);
	free(argv);

	return result;
}

static uc_value_t *
uc_spawn(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *args = uc_fn_arg(0);
	uc_value_t *envs = uc_fn_arg(1);
	pid_t pid;
	size_t i;

	pid = fork();

	if (pid == -1) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			"Unable to fork process: %m");

		return NULL;
	}

	char **argv = xcalloc(sizeof(char *), ucv_array_length(args) + 1);
	char **envv = xcalloc(sizeof(char *), ucv_object_length(envs) + 1);

	for (i = 0; i < ucv_array_length(args); i++)
		argv[i] = ucv_to_string(vm, ucv_array_get(args, i));

	i = 0;
	ucv_object_foreach(envs, k, v) {
		uc_stringbuf_t sbuf = { 0 };

		sprintbuf(&sbuf, "%s=", k);
		ucv_to_stringbuf(vm, &sbuf, v, false);

		envv[i] = sbuf.buf;
	}

	if (pid == 0) {
		execvpe(argv[0], argv, envv);
		exit(-1);
	}

	for (size_t i = 0; argv[i] != NULL; i++)
		free(argv[i]);

	for (size_t i = 0; envv[i] != NULL; i++)
		free(envv[i]);

	free(argv);
	free(envv);

	return ucv_int64_new(pid);
}

static uc_value_t *
uc_kill(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *pidval = uc_fn_arg(0);
	uc_value_t *sigval = uc_fn_arg(1);
	int64_t pid = ucv_int64_get(pidval);
	int64_t signum = -1;

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Unable to convert argument to PID value: %m");

		return NULL;
	}

	if (ucv_type(sigval) == UC_INTEGER) {
		signum = ucv_int64_get(sigval);

		if (errno != 0)
			signum = -1;
	}
	else if (ucv_type(sigval) == UC_STRING) {
		char *signame = ucv_string_get(sigval);

		if (!strncasecmp(signame, "SIG", 3))
			signame += 3;

		for (size_t i = 0; i < UC_SYSTEM_SIGNAL_COUNT; i++) {
			if (uc_system_signal_names[i] == NULL)
				continue;

			if (strcasecmp(signame, uc_system_signal_names[i]) != 0)
				continue;

			signum = i;
			break;
		}
	}

	if (signum < 0 || signum >= UC_SYSTEM_SIGNAL_COUNT ||
	    uc_system_signal_names[signum] == NULL) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid signal number");

		return NULL;
	}

	if (kill(pid, signum) == -1) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			"Error sending %s to pid %zd: %m",
			uc_system_signal_names[signum], pid);

		return NULL;
	}

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_waitpid(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *pidval = uc_fn_arg(0);
	pid_t pid = ucv_to_integer(pidval);
	int rc;

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid PID value");

		return NULL;
	}

	if (waitpid(pid, &rc, 0) == -1) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			"Error waiting for pid %zd: %m", pid);

		return NULL;
	}

	if (WIFEXITED(rc))
		return ucv_int64_new(WEXITSTATUS(rc));
	else if (WIFSIGNALED(rc))
		return ucv_int64_new(-WTERMSIG(rc));
	else if (WIFSTOPPED(rc))
		return ucv_int64_new(-WSTOPSIG(rc));

	return NULL;
}


static const uc_function_list_t getopt_fns[] = {
	{ "getopt", 	uc_getopt },
	{ "spawn",		uc_spawn },
	{ "kill",		uc_kill },
	{ "waitpid",	uc_waitpid },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, getopt_fns);
}
