#include <impl/includes.h>

int main( int argc, char** argv ) {
    logging::setup_console();
    for ( int i = 1; i < argc; ++i ) {
        if ( !_stricmp( argv[i], oxorany( "--verbose" ) ) ||
             !_stricmp( argv[i], oxorany( "-v" ) ) )
            logging::set_verbose( true );
    }

    SetUnhandledExceptionFilter( handler::crash_handler );

    if ( !utility::adjust_privilege( 20 ) )
        return std::getchar();

    logging::info( oxorany( "downloading ntoskrnl PDB..." ) );
    if ( !pdb::load( oxorany( "ntoskrnl.exe" ) ) ) {
        logging::error( oxorany( "could not load PDB" ) );
        return std::getchar();
    }

    logging::success( oxorany( "loaded %zu symbols from %s" ),
        pdb::s_symbols.size(), pdb::s_module_bare.c_str() );

    if ( !service::create() ) {
        logging::error( oxorany( "could not setup service" ) );
        service::unload();
        return std::getchar();
    }

    if ( !driver::initialize() ) {
        logging::error( oxorany( "could not setup driver" ) );
        service::unload();
        return std::getchar();
    }

    if ( !paging::setup() ) {
        logging::error( oxorany( "could not get directory table base" ) );
        service::unload();
        driver::unload();
        return std::getchar();
    }

    if ( !syscall::setup() ) {
        logging::error( oxorany( "could not setup kernel execution" ) );
        service::unload();
        driver::unload();
        return std::getchar();
    }

    spoof::install();

    if ( !service::unload() ) {
        logging::error( oxorany( "could not unload service" ) );
        return std::getchar();
    }

    if ( !driver::unload() ) {
        logging::error( oxorany( "could not unload driver" ) );
        return std::getchar();
    }

    logging::shutdown();
    return std::getchar();
}
