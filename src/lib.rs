/*  Copyright 2014 MaidSafe.net limited
    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").
    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses
    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.
    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe
    Software.                                                                 */


mod routing_table;
use std::marker::MarkerTrait;
trait Foo : MarkerTrait {}
/*  */
/* struct MyFoo; */
/*  */
/* impl Foo for MyFoo {} */
/*  */
struct Bar<'a> {
foo: &'a (Foo + 'a),
}

impl<'a> Bar<'a> {
  fn new(the_foo: &'a Foo) -> Bar<'a> {
    Bar { foo: the_foo }
  }

  fn get_foo(&'a self) -> &'a Foo {
    self.foo
  }
}


/* fn() { */
/*     let myfoo = MyFoo; */
/*     let mybar = Bar::new(&myfoo as &Foo); */
/* } */


#[test]
fn it_works() {
}
