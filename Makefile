TOP_DIR = ../..
include $(TOP_DIR)/tools/Makefile.common

TOP_ABS = $(shell $(TOP_DIR)/runtime/bin/perl -MCwd -e 'print Cwd::abs_path("$(TOP_DIR)") ')

SRC_PERL = $(wildcard scripts/*.pl)
BIN_PERL = $(addprefix $(BIN_DIR)/,$(basename $(notdir $(SRC_PERL))))
LIB_PERL = $(wildcard Bio-KBase-Auth/lib/Bio/KBase/*.pm)

GLOBUS_TOKEN_URL = http://rast.nmpdr.org/goauth/token?grant_type=client_credentials
GLOBUS_PROFILE_URL = http://rast.nmpdr.org/users
TRUST_TOKEN_SIGNERS = https://rast.nmpdr.org/goauth/keys https://user.alpha.patricbrc.org/public_key https://nexus.api.globusonline.org/goauth/keys https://user.patricbrc.org/public_key


#GLOBUS_TOKEN_URL = https://nexus.api.globusonline.org/goauth/token?grant_type=client_credentials
#GLOBUS_PROFILE_URL = https://nexus.api.globusonline.org/users

#TRUST_TOKEN_SIGNERS = https://nexus.api.globusonline.org/goauth/keys
ROLE_SERVICE_URL = https://kbase.us/services/authorization/Roles

TPAGE_ARGS = --define kb_top=$(TARGET) \
    --define kb_runtime=$(DEPLOY_RUNTIME) \
    --define globus_token_url=$(GLOBUS_TOKEN_URL) \
    --define globus_profile_url=$(GLOBUS_PROFILE_URL) \
    --define "trust_token_signers=$(TRUST_TOKEN_SIGNERS)" \
    --define role_service_url=$(ROLE_SERVICE_URL)

DEPLOY_RUNTIME ?= /kb/runtime
TARGET ?= /kb/deployment
DEPLOY_PERL = $(addprefix $(TARGET)/bin/,$(basename $(notdir $(SRC_PERL))))

#KB_PERL_PATH is now just defined from Makefile.common
#KB_PERL_PATH = $(DEPLOY_RUNTIME)/perl5/site_perl
#KB_PERL_PATH = $(TARGET)/lib

# You can change these if you are putting your tests somewhere
# else or if you are not using the standard .t suffix
CLIENT_TESTS = $(wildcard client-tests/*.t)
SCRIPTS_TESTS = $(wildcard script-tests/*.t)
SERVER_TESTS = $(wildcard server-tests/*.t)

SERVICE = authorization_server
SERVICE_DIR = $(TARGET)/services/$(SERVICE)


all: build-libs bin

bin: $(BIN_PERL)

deploy: deploy-client
deploy-client: build-libs deploy-libs deploy-scripts
deploy-service: 

build-libs:
	-mkdir lib;
	$(TPAGE) $(TPAGE_ARGS) Constants.pm.tt > lib/P3AuthConstants.pm

# this target is now included from Makefile.common.rules 
#deploy-libs: build-libs
#	rsync -rv --exclude README lib/. $(TARGET)/lib/.

deploy-docs:
	-mkdir $(TARGET)/services
	-mkdir $(SERVICE_DIR)

	-for l in $(LIB_PERL) ; do \
	name=$$(basename $$l .pm) ; \
	echo $$n ; \
		if [ -f $$l ] ; then \
			$(DEPLOY_RUNTIME)/bin/pod2html -t $(SERVICE) $$l > docs/$$name.html ; \
			$(DEPLOY_RUNTIME)/bin/pod2man $$l > docs/$$name.3 ; \
			if [ $$? -ne 0 ] ; then \
				exit 1 ; \
			fi \
		fi \
	done
	-mkdir $(SERVICE_DIR)/webroot
	cp docs/*.html $(SERVICE_DIR)/webroot/.
	-mkdir -p $(DEPLOY_RUNTIME)/share/man/man3
	-cp docs/*.3 $(DEPLOY_RUNTIME)/share/man/man3

# these targets are now included from Makefile.common.rules 
#deploy-scripts: deploy-perl-scripts deploy-python-scripts
#
#deploy-perl-scripts:
#	export KB_TOP=$(TARGET); \
#	export KB_RUNTIME=$(DEPLOY_RUNTIME); \
#	export KB_PERL_PATH=$(TARGET)/lib ; \
#	for src in $(SRC_PERL) ; do \
#		basefile=`basename $$src`; \
#		base=`basename $$src .pl`; \
#		echo install $$src $$base ; \
#		cp $$src $(TARGET)/plbin ; \
#		$(WRAP_PERL_SCRIPT) "$(TARGET)/plbin/$$basefile" $(TARGET)/bin/$$base ; \
#	done 
#
#deploy-python-scripts:
#	export KB_TOP=$(TARGET); \
#	export KB_RUNTIME=$(DEPLOY_RUNTIME); \
#	export KB_PYTHON_PATH=$(TARGET)/lib ; \
#	for src in $(SRC_PYTHON) ; do \
#		basefile=`basename $$src`; \
#		base=`basename $$src .py`; \
#		echo install $$src $$base ; \
#		cp $$src $(TARGET)/pybin ; \
#		$(WRAP_PYTHON_SCRIPT) "$(TARGET)/pybin/$$basefile" $(TARGET)/bin/$$base ; \
#	done 


test: test-libs test-client test-scripts test-service
	@echo "running library, client and script tests"

test-libs: build-libs
	export PERL5LIB=$(shell pwd)/Bio-KBase-Auth/lib ; \
	cd Bio-KBase-Auth; $(DEPLOY_RUNTIME)/bin/perl ./Build test;

# test-all is deprecated. 
# test-all: test-client test-scripts test-service
#
# What does it mean to test a client. This is a test of a client
# library. If it is a client-server module, then it should be
# run against a running server. You can say that this also tests
# the server, and I agree. You can add a test-service dependancy
# to the test-client target if it makes sense to you. This test
# example assumes there is already a tested running server.
test-client:
	# run each test
	for t in $(CLIENT_TESTS) ; do \
		if [ -f $$t ] ; then \
			$(DEPLOY_RUNTIME)/bin/perl $$t ; \
			if [ $$? -ne 0 ] ; then \
				exit 1 ; \
			fi \
		fi \
	done

# What does it mean to test a script? A script test should test
# the command line scripts. If the script is a client in a client-
# server architecture, then there should be tests against a 
# running server. You can add a test-service dependancy to the
# test-client target. You could also add a deploy-service and
# start-server dependancy to the test-scripts target if it makes
# sense to you. Future versions of the make files for services
# will move in this direction.
test-scripts:
	# run each test
	for t in $(SCRIPT_TESTS) ; do \
		if [ -f $$t ] ; then \
			$(DEPLOY_RUNTIME)/bin/perl $$t ; \
			if [ $$? -ne 0 ] ; then \
				exit 1 ; \
			fi \
		fi \
	done

# What does it mean to test a server. A server test should not
# rely on the client libraries or scripts in so far as you should
# not have a test-service target that depends on the test-client
# or test-scripts targets. Otherwise, a circular dependency
# graph could result.
test-service:
	# run each test
	for t in $(SERVER_TESTS) ; do \
		if [ -f $$t ] ; then \
			$(DEPLOY_RUNTIME)/bin/perl $$t ; \
			if [ $$? -ne 0 ] ; then \
				exit 1 ; \
			fi \
		fi \
	done

include $(TOP_DIR)/tools/Makefile.common.rules
