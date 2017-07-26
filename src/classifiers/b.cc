/*
 * Copyright 2013-2015 Raphael Bost
 *
 * This file is part of ciphermed.

 *  ciphermed is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  ciphermed is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with ciphermed.  If not, see <http://www.gnu.org/licenses/>. 2
 *
 */

#include <classifiers/linear_classifier.hh>

#include <util/util.hh>
#include <util/benchmarks.hh>
#include <ctime>
#include <fstream>
#include<cstdlib>
#include<iostream>
#include<gmpxx.h>
#include<gmp.h>
#include<mpfr.h>


static void bench_linear_classifier_client(const string &hostname, unsigned int model_size, unsigned int nbits_max, unsigned int nRounds = 10)
{
    /*
    cout << "Client for linear classifier\n";
    cout << "Model as dimension " << model_size << "\n";
    cout << nbits_max << " bits of precision" << endl;
    */
    
    try
    {
#ifdef BENCHMARK
        //cout << "BENCHMARK flag set" << endl;
        BENCHMARK_INIT
#endif
        
        boost::asio::io_service io_service;
        
        gmp_randstate_t randstate;
        gmp_randinit_default(randstate);
        gmp_randseed_ui(randstate,time(NULL));
        
        srand(time(NULL));
        
	//assert(nbits_max > model_size + 1);
        unsigned int nbits = nbits_max - model_size - 1;
	nbits = 10;
        long two_nbits = 1 << nbits;

	clock_t beg, end;

	ofstream fout("d.out");

	//client generate value
        vector<mpz_class> values;
	double v[model_size], vmax, vmin;
	vmax = -999999;
	vmin =  999999;
	two_nbits = 100;
	for(size_t i = 0; i < model_size; i++) {
	    v[i] = rand() % two_nbits;
	    if(rand() % 2)  v[i] *= -1;
	    if(vmax < v[i]) vmax = v[i];
	    if(vmin > v[i]) vmin = v[i];
	    long tmp = 1e13 * v[i];
	    values.push_back(tmp);
	    fout<<v[i]<<", ";
	}
	fout<<endl;

	//generate key
	auto sk = Paillier_priv::keygen(randstate, 600);
	Paillier_priv pp(sk, randstate);
	auto pk = pp.pubkey();
	Paillier p(pk ,randstate);

	//server read model
	//std::ifstream fin1("../../ml/out/credit.model");
	std::ifstream fin1("../../classifiers/model.out");
	vector<mpz_class> model;
	double v1;
	for(size_t i = 0; i < model_size; i++) {
	    fin1>>v1;
	    fout<<v1<<", ";
	    long v1_int;
	    v1_int = v1 * 1e13;
	    model.push_back(v1_int);
	}
	fout<<endl<<endl;

	//plaintext dot production
	mpz_class psu = 0;
	for(size_t i = 0; i < model_size; i++) {
	    //plaintext
	    psu += model[i] * values[i];
	}
	std::cout<<psu<<endl;

	//encryption
	vector<mpz_class> ct0(model_size);
	for(size_t i = 0; i < model_size; i++) {
	    ct0[i] = p.encrypt(values[i]);
	}

	//dot production 
	for(size_t ii = 0; ii < 100; ii++) {
	    //test 100 times
	    mpz_class sum = p.encrypt(0);
	    vector<mpz_class> nn;

	    for(size_t i = 0; i < model_size; i++) {
		//noise
		mpfr_t noise;
		mpfr_t tmp;
		mpfr_init2(tmp, 50);
		mpfr_init2(noise, 50);

		//long long int scale = 1e9;
		mpfr_urandom(noise, randstate, MPFR_RNDD);
		if(rand() % 2) mpfr_mul_si(noise, noise,  1, MPFR_RNDD);
		else mpfr_mul_si(noise, noise, -1, MPFR_RNDD);
		mpfr_mul_d(noise, noise, 0.5, MPFR_RNDD);
		mpfr_set(tmp, noise, MPFR_RNDD);
		mpfr_abs(noise, noise, MPFR_RNDD);
		mpfr_mul_d(noise, noise, -2, MPFR_RNDD);
		mpfr_add_si(noise, noise , 1, MPFR_RNDD);
		mpfr_log(noise, noise, MPFR_RNDD);
		mpfr_mul_d(noise, noise, mpfr_sgn(tmp), MPFR_RNDD);
		//mpz_class b(1e13 * 1e2 * scale * model[i]);
		//mpz_class b(1e13 * 1e2 * model[i]);
		mpz_class b(model[i] * (vmax - vmin) * 1e13 * 1e2);
		mpfr_mul_z(noise, noise, b.get_mpz_t(), MPFR_RNDD);

		mpz_t n1;
		mpz_init2(n1, 50);
		mpfr_get_z(n1, noise, MPFR_RNDD);
		mpz_class nn1(n1);
		fout<<nn1<<", ";
		nn.push_back(nn1);
	    }
	    fout<<endl;

	    for(size_t i = 0; i < model_size; i++) {
		sum = p.add(sum, p.constMult(model[i], ct0[i]));
		sum = p.add(sum, p.encrypt(nn[i]));
	    }

	    mpz_class aa = pp.decrypt(sum);
	    if(aa > vmax * model_size * 1e30)
		aa = aa - pk[0];
	    else
		aa = aa;
	    std::cout<<aa;


	std::cout<<endl;
	}



        Bench_Linear_Classifier_Client client(io_service, randstate,1024,100,values,nbits_max, nRounds);
        
        client.connect(io_service, hostname);
        
        client.run();
        
        //        client.disconnect();
    }
    catch (std::exception& e)
    {
        //std::cout << "Exception: " << e.what() << std::endl;
    }
    
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: client <host> <model_size>" << std::endl;
        return 1;
    }
    string hostname(argv[1]);
    unsigned int model_size(atoi(argv[2]));

//    test_linear_classifier_client(hostname,model_size);
    bench_linear_classifier_client(hostname,model_size,64,10);
    
    return 0;
}
