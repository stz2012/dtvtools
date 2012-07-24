#include "b_cas_card.h"
#include "b_cas_card_error_code.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <yakisoba/Global.h>
#include <yakisoba/Decoder.h>
#include <yakisoba/Keys.h>

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 inner structures
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
typedef struct {
	
	long               card;

	B_CAS_INIT_STATUS  stat;
	
} B_CAS_CARD_PRIVATE_DATA;

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 constant values
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static uint8_t BCAS_SYSTEM_KEY[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t BCAS_INIT_CBC[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static int64_t BCAS_CARD_ID = 0x0000000000;

static int32_t BCAS_CA_SYSTEM_ID = 0x0000;

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 function prottypes (interface method)
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static void release_b_cas_card(void *bcas);
static int init_b_cas_card(void *bcas);
static int get_init_status_b_cas_card(void *bcas, B_CAS_INIT_STATUS *stat);
static int get_id_b_cas_card(void *bcas, B_CAS_ID *dst);
static int get_pwr_on_ctrl_b_cas_card(void *bcas, B_CAS_PWR_ON_CTRL_INFO *dst);
static int proc_ecm_b_cas_card(void *bcas, B_CAS_ECM_RESULT *dst, uint8_t *src, int len);
static int proc_emm_b_cas_card(void *bcas, uint8_t *src, int len);
static int init_bcas_param(void);

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 global function implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
B_CAS_CARD *create_b_cas_card()
{
	int n;
	
	B_CAS_CARD *r;
	B_CAS_CARD_PRIVATE_DATA *prv;
	
	if( init_bcas_param() < 0 ) {
		return NULL;
	}
	n = sizeof(B_CAS_CARD) + sizeof(B_CAS_CARD_PRIVATE_DATA);
	prv = (B_CAS_CARD_PRIVATE_DATA *)calloc(1, n);
	if(prv == NULL){
		return NULL;
	}

	r = (B_CAS_CARD *)(prv+1);

	r->private_data = prv;

	r->release = release_b_cas_card;
	r->init = init_b_cas_card;
	r->get_init_status = get_init_status_b_cas_card;
	r->get_id = get_id_b_cas_card;
	r->get_pwr_on_ctrl = get_pwr_on_ctrl_b_cas_card;
	r->proc_ecm = proc_ecm_b_cas_card;
	r->proc_emm = proc_emm_b_cas_card;

	return r;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 function prottypes (private method)
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static B_CAS_CARD_PRIVATE_DATA *private_data(void *bcas);
static void teardown(B_CAS_CARD_PRIVATE_DATA *prv);

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 interface method implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static void release_b_cas_card(void *bcas)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if(prv == NULL){
		/* do nothing */
		return;
	}

	teardown(prv);
	free(prv);
}

static int init_b_cas_card(void *bcas)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if(prv == NULL){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	teardown(prv);

    prv->card = 1;
    
	memcpy(prv->stat.system_key, BCAS_SYSTEM_KEY, 32);
	memcpy(prv->stat.init_cbc, BCAS_INIT_CBC, 8);
	prv->stat.bcas_card_id = BCAS_CARD_ID;
	prv->stat.card_status = 0;
	prv->stat.ca_system_id = BCAS_CA_SYSTEM_ID;

    BCAS::Keys::RegisterAll();

	return 0;
}

static int get_init_status_b_cas_card(void *bcas, B_CAS_INIT_STATUS *stat)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) || (stat == NULL) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->card == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	memcpy(stat, &(prv->stat), sizeof(B_CAS_INIT_STATUS));

	return 0;
}

static int get_id_b_cas_card(void *bcas, B_CAS_ID *dst)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) || (dst == NULL) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->card == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

    memset(dst, 0, sizeof(B_CAS_ID));

	return 0;
}

static int get_pwr_on_ctrl_b_cas_card(void *bcas, B_CAS_PWR_ON_CTRL_INFO *dst)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) || (dst == NULL) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->card == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	memset(dst, 0, sizeof(B_CAS_PWR_ON_CTRL_INFO));

	return 0;
}

static int proc_ecm_b_cas_card(void *bcas, B_CAS_ECM_RESULT *dst, uint8_t *src, int len)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) ||
	    (dst == NULL) ||
	    (src == NULL) ||
	    (len < 1) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->card == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

    if (BCAS::Decoder::DecodeECM(src, len, dst->scramble_key, NULL) < 0) {
        return B_CAS_CARD_ERROR_TRANSMIT_FAILED;
    }
    dst->return_code = 0x0800;

	return 0;
}

static int proc_emm_b_cas_card(void *bcas, uint8_t *src, int len)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) ||
	    (src == NULL) ||
	    (len < 1) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->card == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	return 0;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 private method implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static B_CAS_CARD_PRIVATE_DATA *private_data(void *bcas)
{
	B_CAS_CARD_PRIVATE_DATA *r;
	B_CAS_CARD *p;

	p = (B_CAS_CARD *)bcas;
	if(p == NULL){
		return NULL;
	}

	r = (B_CAS_CARD_PRIVATE_DATA *)(p->private_data);
	if( ((void *)(r+1)) != ((void *)p) ){
		return NULL;
	}

	return r;
}

static void teardown(B_CAS_CARD_PRIVATE_DATA *prv)
{
	if(prv->card != 0){
		prv->card = 0;
	}
}

static int init_bcas_param(void)
{
	static const char *init_file_path[] = {
		"bcasid.inf",
		"~/.bcas/bcasid.inf",
		"/etc/bcasid.inf",
		"/usr/local/etc/bcasid.inf",
		"/usr/share/bcas/bcasid.inf",
		"/lib/bcas/bcasid.inf",
		"/usr/lib/bcas/bcasid.inf",
		"/usr/local/lib/bcas/bcasid.inf",
		"/usr/local/share/bcas/bcasid.inf",
		NULL
	};
	char buffer[256];
	int i, p;
	int f_init_card_id, f_init_ca_system_id, f_init_cbc, f_init_system_key;
	FILE *fp;
	
	i = p = f_init_card_id = f_init_ca_system_id = f_init_cbc = f_init_system_key = 0;
	
	/* find bcasid.inf */
	while( init_file_path[p] != NULL ) {
		if( access( init_file_path[p], R_OK ) == 0 ) break;
		p++;
	}
	if( init_file_path[p] == NULL ) {
		fprintf(stderr, "Cant find inf\n");
		return -1;
	}
	/* read bcasid.inf */
	fp = fopen( init_file_path[p] , "r" );
	if( fp == NULL ) return -1;
	
	while( fgets( buffer, 256, fp) != NULL ) {
		char *valp = strchr( buffer, '=' );
		if( valp == NULL ) continue;
		*valp = '\0';
		valp++;
		
		char *lp = strchr( valp, '\n' );
		if( lp != NULL ) *lp = '\0';
		
		/* card_id */
		if( strcmp( buffer, "card_id" ) == 0 ) {
			if( sscanf( valp, "0x%llx", &(BCAS_CARD_ID) ) == 0 ) break;
			f_init_card_id = 1;
		}
		/* ca_system_id */
		else if( strcmp( buffer, "ca_system_id" ) == 0 ) {
			if( sscanf( valp, "0x%02x",  &(BCAS_CA_SYSTEM_ID) ) == 0 ) break;
			f_init_ca_system_id = 1;
		}
		/* init_cbc[8] */
		else if( strcmp( buffer, "init_cbc" ) == 0 ) {
			for( i = 0; i < 8; i++ ) {
				int value;
				char *cp = strchr( valp, ',' );
				if( cp != NULL ) *cp = '\0';
				if( sscanf( valp, "0x%02x", &value ) == 0 ) break;
				BCAS_INIT_CBC[i] = 0xFF & value;
				valp = cp + 1;
			}
			if( i < 8 ) break;
			f_init_cbc = 1;
		}
		/* system_key[32] */
		else if( strcmp( buffer, "system_key" ) == 0 ) {
			for( i = 0; i < 32; i++ ) {
				int value;
				char *cp = strchr( valp, ',' );
				if( cp != NULL ) *cp = '\0';
				if( sscanf( valp, "0x%02x",  &value ) == 0 ) break;
				BCAS_SYSTEM_KEY[i] = 0xFF & value;
				valp = cp + 1;
			}
			if( i < 32 ) break;
			f_init_system_key = 1;
		}
	}
	fclose(fp);
	if( f_init_card_id && f_init_ca_system_id && f_init_cbc && f_init_system_key ) return 0;
	
	return -1;
}
