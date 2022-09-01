#include "b_cas_card.h"
#include "b_cas_card_error_code.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

	B_CAS_ID           id;	
} B_CAS_CARD_PRIVATE_DATA;

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 constant values
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static uint8_t BCAS_SYSTEM_KEY[] = {
    0x36, 0x31, 0x04, 0x66, 0x4b, 0x17, 0xea, 0x5c,
    0x32, 0xdf, 0x9c, 0xf5, 0xc4, 0xc3, 0x6c, 0x1b,
    0xec, 0x99, 0x39, 0x21, 0x68, 0x9d, 0x4b, 0xb7,
    0xb7, 0x4e, 0x40, 0x84, 0x0d, 0x2e, 0x7d, 0x98
};

static uint8_t BCAS_INIT_CBC[] = {
    0xfe, 0x27, 0x19, 0x99, 0x19, 0x69, 0x09, 0x11
};

static int64_t BCAS_CARD_ID = 0x0000000000;

static uint8_t BCAS_CARD_ID_GEN[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static int32_t BCAS_CA_SYSTEM_ID = 0x0005;

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

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 function prottypes (private method)
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static B_CAS_CARD_PRIVATE_DATA *private_data(void *bcas);
static void teardown(B_CAS_CARD_PRIVATE_DATA *prv);
static int init_bcas_param(void);
static int64_t load_be_uint48(uint8_t *p);

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

	prv->id.data = &BCAS_CARD_ID;
	prv->id.count = 1;
	memcpy(dst, &(prv->id), sizeof(B_CAS_ID));

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
	uint16_t id01,id23,id45,id67;
	srand(time(NULL) & 0xffff);
	srand(rand());
	id01 = 0x0007;
	id23 = rand();
	id45 = rand();
	id67 = id01 ^ id23 ^ id45;
	BCAS_CARD_ID_GEN[0] = id01 >> 8;
	BCAS_CARD_ID_GEN[1] = id01 & 0xff;
	BCAS_CARD_ID_GEN[2] = id23 >> 8;
	BCAS_CARD_ID_GEN[3] = id23 & 0xff;
	BCAS_CARD_ID_GEN[4] = id45 >> 8;
	BCAS_CARD_ID_GEN[5] = id45 & 0xff;
	BCAS_CARD_ID_GEN[6] = id67 >> 8;
	BCAS_CARD_ID_GEN[7] = id67 & 0xff;
	BCAS_CARD_ID = load_be_uint48(&BCAS_CARD_ID_GEN[0]);

	return 0;
}

static int64_t load_be_uint48(uint8_t *p)
{
	int i;
	int64_t r;

	r = p[0];
	for(i=1;i<6;i++){
		r <<= 8;
		r |= p[i];
	}

	return r;
}

