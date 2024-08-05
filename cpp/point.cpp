#include"bits/stdc++.h"
#include "point.h"
#include "Lib/ecp_Ed25519.h"
#include "Lib/arch.h"
#include "Lib/core.h"
#include "Lib/big_B256_56.h"
#include "Lib/randapi.h"
using namespace Ed25519;
using namespace std;

void Point::Point_Generation(ECP G)
{
    using namespace Ed25519;
    
    ECP P;
    ECP_generator(&P);
    if (ECP_isinf(&P) == 0)
    {
        cout << "Point at infinity" << endl;
        exit(0);
    }
    else
    {
        ECP_copy(&G, &P);
        cout << "Point generated" << endl;
        ECP_output(&G);
    }
}
