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

#include <mpc/lsic.hh>
#include <mpc/private_comparison.hh>
#include <mpc/enc_comparison.hh>
#include <mpc/rev_enc_comparison.hh>
#include <mpc/linear_enc_argmax.hh>

#include <classifiers/linear_classifier.hh>

#include <protobuf/protobuf_conversion.hh>
#include <net/message_io.hh>
#include <util/util.hh>
#include <fstream>
#include <vector>
#include <omp.h>


Linear_Classifier_Server::Linear_Classifier_Server(gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &model, size_t bit_size)
: Server(state, Linear_Classifier_Server::key_deps_descriptor(), keysize, lambda), enc_model_(model.size()), bit_size_(bit_size)
{
    for (size_t i = 0; i < enc_model_.size(); i++) {
	enc_model_[i] = paillier_->encrypt(model[i]);
    }
}

Server_session* Linear_Classifier_Server::create_new_server_session(tcp::socket &socket)
{
    return new Linear_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}

void Linear_Classifier_Server_session::run_session()
{
    try {
        exchange_keys();
        
        ScopedTimer *t;
        RESET_BYTE_COUNT
        RESET_BENCHMARK_TIMER

        t = new ScopedTimer("Server: Compute dot product");
        help_compute_dot_product(linear_server_->enc_model(),true);
        delete t;
        
        t = new ScopedTimer("Server: Compare enc data");
        help_enc_comparison(linear_server_->bit_size(), GC_PROTOCOL);
        delete t;

#ifdef BENCHMARK
        cout << "Benchmark: " << GET_BENCHMARK_TIME << " ms" << endl;
        cout << IOBenchmark::byte_count() << " exchanged bytes" << endl;
        cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif

    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    delete this;
}


Linear_Classifier_Client::Linear_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &vals, size_t bit_size)
: Client(io_service,state,Linear_Classifier_Server::key_deps_descriptor(),keysize,lambda), bit_size_(bit_size),values_(vals)
{
    
}

bool Linear_Classifier_Client::run()
{
    // get public keys
    RESET_BYTE_COUNT
    exchange_keys();
#ifdef BENCHMARK
    const double to_kB = 1 << 10;
    cout << "Key exchange: " <<  (IOBenchmark::byte_count()/to_kB) << " kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    
    ScopedTimer *t;
    RESET_BYTE_COUNT
    RESET_BENCHMARK_TIMER
    // prepare data
    vector <mpz_class> x = values_;
    x.push_back(-1);
    
    t = new ScopedTimer("Client: Compute dot product");
    // compute the dot product
    mpz_class v = compute_dot_product(x);
    mpz_class w = 1; // encryption of 0
    delete t;

    t = new ScopedTimer("Client: Compare enc data");
    // build the comparator over encrypted data
    bool result = enc_comparison(v,w,bit_size_,GC_PROTOCOL);
    delete t;
#ifdef BENCHMARK
    cout << "Benchmark: " << GET_BENCHMARK_TIME << " ms" << endl;
    cout << (IOBenchmark::byte_count()/to_kB) << " exchanged kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    return result;
}


Bench_Linear_Classifier_Server::Bench_Linear_Classifier_Server(gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &model, size_t bit_size, unsigned int nRounds)
: Server(state, Linear_Classifier_Server::key_deps_descriptor(), keysize, lambda), enc_model_(model.size()), bit_size_(bit_size), nRounds_(nRounds)
{
    Timer t;
    t.lap();

#pragma omp parallel for
    for (size_t i = 0; i < enc_model_.size(); i++) {
	enc_model_[i] = paillier_->encrypt(model[i]);
    }

    cout<<"TTTT "<<t.lap_ms();
}

Server_session* Bench_Linear_Classifier_Server::create_new_server_session(tcp::socket &socket)
{
    return new Bench_Linear_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}

void Bench_Linear_Classifier_Server_session::run_session()
{
    try {
        exchange_keys();
        
        double server_time = 0.;
        unsigned int nRounds = linear_server_->nRounds();
        for (unsigned int i = 0; i < nRounds; i++) {
            RESET_BENCHMARK_TIMER
            
            help_compute_dot_product(linear_server_->enc_model(),true);
            
            help_enc_comparison(linear_server_->bit_size(), GC_PROTOCOL);
            
            server_time += GET_BENCHMARK_TIME;
//            cout << "Round #" << i << " done" << endl;
        }
#ifdef BENCHMARK
        cout << "Average time for " << nRounds << " rounds: " << endl;
        cout << "Server time: " << server_time/nRounds << endl;
#endif

    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    delete this;
}


Bench_Linear_Classifier_Client::Bench_Linear_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &vals, size_t bit_size, unsigned int nRounds)
: Client(io_service,state,Linear_Classifier_Server::key_deps_descriptor(),keysize,lambda), bit_size_(bit_size),values_(vals), nRounds_(nRounds)
{
    
}

void Bench_Linear_Classifier_Client::run(int num)
{
    // get public keys
    RESET_BYTE_COUNT
    exchange_keys();
#ifdef BENCHMARK
    const double to_kB = 1 << 10;
    cout << "Key exchange: " <<  (IOBenchmark::byte_count()/to_kB) << " kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    double compare_time = 0., dot_prod_time = 0., client_time = 0.;
    Timer t;

    RESET_BYTE_COUNT

	ifstream fin1("../../classifiers/lbp_lfw1000.out");
	ifstream fin2("../../classifiers/A1000.out");
	ifstream fin3("../../classifiers/G1000.out");

	vector<vector<mpz_class> > myV;
	vector<vector<mpz_class> > myA;
	vector<vector<mpz_class> > myG;
	myV.resize(12792, vector<mpz_class>(160, 0));
	myA.resize(160,   vector<mpz_class>(160, 0));
	myG.resize(160,   vector<mpz_class>(160, 0));
	vector<mpz_class> myXX;
	vector<mpz_class> myT;

	double tt;
	long tt2;
	for(int i = 0; i < 12792; i++) 
	    for(int j = 0; j < 160; j++)  {
		if(i < 160) {
		    fin2>>tt;
		    tt2 = tt * 1e13;
		    myA[i][j] = tt2;
		    fin3>>tt;
		    tt2 = tt * 1e13;
		    myG[i][j] = tt2;
		}
		fin1>>tt;
		tt2 = tt * 1e13;
		myV[i][j] = tt2;
	    }

	cout<<"INT "<<num<<endl;
	vector<mpz_class> myX;
	for(int i = 0; i < 160; i++) {
	    myX.push_back(myV[num][i]);
	}
	vector<mpz_class> myY = compute_dot_product2();

	Paillier &p = *server_paillier_;
	mpz_class tmp = 0;
	mpz_class emp = 1;
	mpz_class emp2 = 1;
	mpz_class tot = 1;
	mpz_class t0 = 0;
	mpz_class t1 = 1;
	mpz_class t2 = 1;
	vector<mpz_class> tt0(25600);
	vector<mpz_class> tt1(25600);

	t.lap();
	for(int i = 0; i < 160; i++) {
	    tmp = 0;
	    for(int j = 0; j < 160; j++) {
		myXX.push_back(myX[i] * myX[j]);
		tmp += myX[j] * myG[j][i];
	    }
	    myT.push_back(tmp);
	}
	cout<<"G TIME: "<<t.lap_ms()<<endl;

	tmp = 0;
        t.lap(); // reset timer
#pragma omp parallel for
	for(int i = 0; i < 160; i++) {
	    /*
	    t0 = 0;
	    t1 = 1;
	    t2 = 1;
	    */
	    for(int j = 0; j < 160; j++) {
		tt0[i * 160 + j] = myXX[i * 160 + j] * myA[i][j];
		tt1[i * 160 + j] = p.constMult(myA[i][j], myY[i * 160 + j]);

		/*
		t0 = t0 + myXX[i * 160 + j] * myA[i][j];
		t1 = p.add(t1, p.constMult(myA[i][j], myY[i * 160 + j]));
		if(i == 0)
		    t2 = p.add(t2, p.constMult(myT[j], myY[25600 + j]));
		*/
	    }
	    /*
	    tmp = tmp + t0;
	    emp = p.add(emp, t1);
	    if(i == 0) emp2 = p.add(emp2, t2);
	    */
	}

	for(int i = 0; i < 160; i++) {
	    t0 = 1;
	    for(int j = 0; j < 160; j++) {
		tmp = tmp + tt0[i* 160 + j];
		t0 = p.add(t0, tt1[i*160 + j]);
		if(i == 0)
		    emp2 = p.add(emp2, p.constMult(myT[j], myY[25600 + j]));
	    }
	    emp = p.add(emp, t0);
	}
	tot = p.add(tot, p.encrypt(tmp));
	tot = p.add(tot, emp);
	tot = p.add(tot, p.constMult(-2, emp2));
	tt2 = -169;
	tmp = tt2 * 1e38;
	tot = p.add(tot, p.encrypt(tmp));
	cout<<"EM ALGORITHM TIME: "<<t.lap_ms()<<endl;

	
        RESET_BENCHMARK_TIMER

        // compute the dot product
        mpz_class w = 1; // encryption of 0
        
        //dot_prod_time += t.lap_ms();
	t.lap();
        // build the comparator over encrypted data
        bool result = enc_comparison(tot,w,bit_size_,GC_PROTOCOL);	
	cout<<result<<endl;
	if(result == 0)
	    cout<<"\n>>>>>>> IntraPersonal"<<endl;
	else
	    cout<<"\n>>>>>>> InterPersonal"<<endl;

        compare_time += t.lap_ms();

        client_time += GET_BENCHMARK_TIME;
	cout<<"COMPARE TIME: "<<client_time<<endl;


/*
#ifdef BENCHMARK
    cout << "Average time for " << nRounds_ << " rounds: " << endl;
    cout << "Client time: " << client_time/nRounds_ << endl;
    cout << "Compare time: " << compare_time/nRounds_ << endl;
    cout << "Dot product time: " << dot_prod_time/nRounds_ << endl;
    cout << (IOBenchmark::byte_count()/(to_kB*nRounds_)) << " exchanged kB per round" << endl;
    cout << IOBenchmark::interaction_count()/nRounds_ << " interactions per round" << endl;
#endif
*/

}
