
#include "DExceptionHelper.h"

void test()
{
	double *ptr = NULL;
	*ptr = 1/0;
}

void main()
{
	try
	{
		test();
	}
	catch(...)
	{
		
	}
}
