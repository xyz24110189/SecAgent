#ifndef KOAL_GLOBAL_H
#define KOAL_GLOBAL_H

#if defined(_WIN32)
	#if defined(KOAL_SEC_EXPORT)
		#define KOAL_SEC_API __declspec(dllexport)
	#else
		#define KOAL_SEC_API __declspec(dllimport)
	#endif
#else
	#define KOAL_SEC_API //nothing
#endif					

#endif//KOAL_GLOBAL_H