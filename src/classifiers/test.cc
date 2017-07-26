#include<cstdlib>
#include<iostream>
#include<fstream>
#include<gmpxx.h>
using namespace std;

//int main(int argc, char** argv) {
void testtt(){
    cout<<"AAAAAAAAAAAAAAA";

    /*
    cout.precision(20);
    int modelsize = 30;

    mpf_t model[modelsize];
    mpf_t data[modelsize][2];
    mpf_t x1[modelsize];

    for(int i = 0; i < modelsize; i++) {
	mpf_init2(model[i], 100);
	mpf_init2(data[i][0], 100);
	mpf_init2(data[i][1], 100);
	mpf_init2(x1[i], 100);
    }

    ifstream fin1("model.out");
    ifstream fin2("data.out");

    for(int i = 0; i < modelsize; i++) {
	fin1>>model[i];
	fin2>>data[i][0]>>data[i][1];
    }

    srand(time(NULL));
    for(int i = 0; i < modelsize; i++) {
	mpf_t seed;
	mpf_init2(seed, 100);
	mpf_set_d(seed, (double)rand() / (RAND_MAX + 1.0));
	mpf_sub(x1[i], data[i][0], data[i][1]);
	mpf_mul(x1[i], x1[i], seed);
	mpf_add(x1[i], x1[i], data[i][1]);
	//cout<<x1[i]<<endl;
    }

    mpf_t scale, epilson;
    mpf_init2(scale, 100);
    mpf_init2(epilson, 100);
    mpf_set_str(scale, argv[1], 10);
    mpf_set_str(epilson, argv[1], 10);
    cout<<scale<<endl;
    */

}
