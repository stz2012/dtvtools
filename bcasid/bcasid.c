#include <stdio.h>
#include "portable.h"
#include "b_cas_card.h"


int main(void)
{
	int r, i;
	B_CAS_CARD *bcas;
	B_CAS_INIT_STATUS stat;

	bcas = create_b_cas_card();
	if( bcas == NULL ) {
		return( fprintf( stderr,"Can't create b_cas_card\n") );
	}

	r = bcas->init(bcas);
	if( r < 0 ) {
		return( fprintf( stderr, "Can't init bcas\n") );
	}

	r = bcas->get_init_status(bcas, &stat);
	if( r < 0 ) {
		return( fprintf( stderr, "Can't get init status\n") );
	}

	/* card_id */
	fprintf( stdout, "card_id=0x%llx\n", stat.bcas_card_id );

	/* ca_system_id */
	fprintf( stdout, "ca_system_id=0x%x\n", stat.ca_system_id );

	/* init_cbc[8] */
	fprintf( stdout, "init_cbc=" );
	for( i = 0 ; i < 8; i++ ) {
		fprintf( stdout, "0x%02x", stat.init_cbc[i] );
		if( i != 7 ) fprintf( stdout, "," );
	}
	fprintf( stdout, "\n" );
	
	/* system_key[32] */
	fprintf( stdout, "system_key=" );
	for( i = 0 ; i < 32; i++ ) {
		fprintf( stdout, "0x%02x", stat.system_key[i] );
		if( i != 31 ) fprintf( stdout, "," );
	}
	fprintf( stdout, "\n" );
	
	return 0;
}

